/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#if !ADB_HOST

#define TRACE_TAG ADB_WIRELESS

#include "adb_wifi.h"

#include <unistd.h>
#include <optional>

#include <adbd_auth.h>
#include <android-base/properties.h>

#include "adb.h"
#include "daemon/mdns.h"
#include "sysdeps.h"
#include "transport.h"

using namespace android::base;

namespace {

static AdbdAuthContext* auth_ctx;

static void adb_disconnected(void* unused, atransport* t);
static struct adisconnect adb_disconnect = {adb_disconnected, nullptr};

static void adb_disconnected(void* unused, atransport* t) {
    LOG(INFO) << "ADB wifi device disconnected";
    CHECK(t->auth_id.has_value());
    adbd_auth_tls_device_disconnected(auth_ctx, kAdbTransportTypeWifi, t->auth_id.value());
}

// TODO(b/31559095): need bionic host so that we can use 'prop_info' returned
// from WaitForProperty
#if defined(__ANDROID__)

class TlsServer {
  public:
    explicit TlsServer(int port);
    virtual ~TlsServer();
    bool Start();
    uint16_t port() { return port_; };

  private:
    void OnFdEvent(int fd, unsigned ev);
    static void StaticOnFdEvent(int fd, unsigned ev, void* opaque);

    fdevent* fd_event_ = nullptr;
    uint16_t port_;
};  // TlsServer

TlsServer::TlsServer(int port) : port_(port) {}

TlsServer::~TlsServer() {
    fdevent* fde = fd_event_;
    fdevent_run_on_main_thread([fde]() {
        if (fde != nullptr) {
            fdevent_destroy(fde);
        }
    });
}

bool TlsServer::Start() {
    std::condition_variable cv;
    std::mutex mutex;
    std::optional<bool> success;
    auto callback = [&](bool result) {
        {
            std::lock_guard<std::mutex> lock(mutex);
            success = result;
        }
        cv.notify_one();
    };

    std::string err;
    unique_fd fd(network_inaddr_any_server(port_, SOCK_STREAM, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start TLS server [" << err << "]";
        return false;
    }
    close_on_exec(fd.get());
    int port = socket_get_local_port(fd.get());
    if (port <= 0 || port > 65535) {
        LOG(ERROR) << "Invalid port for tls server";
        return false;
    }
    port_ = static_cast<uint16_t>(port);
    LOG(INFO) << "adbwifi started on port " << port_;

    std::unique_lock<std::mutex> lock(mutex);
    fdevent_run_on_main_thread([&]() {
        fd_event_ = fdevent_create(fd.release(), &TlsServer::StaticOnFdEvent, this);
        if (fd_event_ == nullptr) {
            LOG(ERROR) << "Failed to create fd event for TlsServer.";
            callback(false);
            return;
        }
        callback(true);
    });

    cv.wait(lock, [&]() { return success.has_value(); });
    if (!*success) {
        LOG(INFO) << "TlsServer fdevent_create failed";
        return false;
    }
    fdevent_set(fd_event_, FDE_READ);
    LOG(INFO) << "TlsServer running on port " << port_;

    return *success;
}

// static
void TlsServer::StaticOnFdEvent(int fd, unsigned ev, void* opaque) {
    auto server = reinterpret_cast<TlsServer*>(opaque);
    server->OnFdEvent(fd, ev);
}

void TlsServer::OnFdEvent(int fd, unsigned ev) {
    if ((ev & FDE_READ) == 0 || fd != fd_event_->fd.get()) {
        LOG(INFO) << __func__ << ": No read [ev=" << ev << " fd=" << fd << "]";
        return;
    }

    unique_fd new_fd(adb_socket_accept(fd, nullptr, nullptr));
    if (new_fd >= 0) {
        LOG(INFO) << "New TLS connection [fd=" << new_fd.get() << "]";
        close_on_exec(new_fd.get());
        disable_tcp_nagle(new_fd.get());
        std::string serial = android::base::StringPrintf("host-%d", new_fd.get());
        register_socket_transport(
                std::move(new_fd), std::move(serial), port_, 1,
                [](atransport*) { return ReconnectResult::Abort; }, true);
    }
}

TlsServer* sTlsServer = nullptr;
const char kWifiPortProp[] = "service.adb.tls.port";

const char kWifiEnabledProp[] = "persist.adb.tls_server.enable";

static void enable_wifi_debugging() {
    start_mdnsd();

    if (sTlsServer != nullptr) {
        delete sTlsServer;
    }
    sTlsServer = new TlsServer(0);
    if (!sTlsServer->Start()) {
        LOG(ERROR) << "Failed to start TlsServer";
        delete sTlsServer;
        sTlsServer = nullptr;
        return;
    }

    // Start mdns connect service for discovery
    register_adb_secure_connect_service(sTlsServer->port());
    LOG(INFO) << "adb wifi started on port " << sTlsServer->port();
    SetProperty(kWifiPortProp, std::to_string(sTlsServer->port()));
}

static void disable_wifi_debugging() {
    if (sTlsServer != nullptr) {
        delete sTlsServer;
        sTlsServer = nullptr;
    }
    if (is_adb_secure_connect_service_registered()) {
        unregister_adb_secure_connect_service();
    }
    kick_all_tcp_tls_transports();
    LOG(INFO) << "adb wifi stopped";
    SetProperty(kWifiPortProp, "");
}

// Watches for the #kWifiEnabledProp property to toggle the TlsServer
static void start_wifi_enabled_observer() {
    std::thread([]() {
        bool wifi_enabled = false;
        while (true) {
            std::string toggled_val = wifi_enabled ? "0" : "1";
            LOG(INFO) << "Waiting for " << kWifiEnabledProp << "=" << toggled_val;
            if (WaitForProperty(kWifiEnabledProp, toggled_val)) {
                wifi_enabled = !wifi_enabled;
                LOG(INFO) << kWifiEnabledProp << " changed to " << toggled_val;
                if (wifi_enabled) {
                    enable_wifi_debugging();
                } else {
                    disable_wifi_debugging();
                }
            }
        }
    }).detach();
}
#endif  //__ANDROID__

}  // namespace

void adbd_wifi_init(AdbdAuthContext* ctx) {
    auth_ctx = ctx;
#if defined(__ANDROID__)
    start_wifi_enabled_observer();
#endif  //__ANDROID__
}

void adbd_wifi_secure_connect(atransport* t) {
    t->AddDisconnect(&adb_disconnect);
    handle_online(t);
    send_connect(t);
    LOG(INFO) << __func__ << ": connected " << t->serial;
    t->auth_id = adbd_auth_tls_device_connected(auth_ctx, kAdbTransportTypeWifi, t->auth_key.data(),
                                                t->auth_key.size());
}

#endif /* !HOST */
