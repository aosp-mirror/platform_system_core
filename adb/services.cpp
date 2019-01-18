/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <thread>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "services.h"
#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"

namespace {

void service_bootstrap_func(std::string service_name, std::function<void(unique_fd)> func,
                            unique_fd fd) {
    adb_thread_setname(android::base::StringPrintf("%s svc %d", service_name.c_str(), fd.get()));
    func(std::move(fd));
}

}  // namespace

unique_fd create_service_thread(const char* service_name, std::function<void(unique_fd)> func) {
    int s[2];
    if (adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return unique_fd();
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

#if !ADB_HOST
    if (strcmp(service_name, "sync") == 0) {
        // Set file sync service socket to maximum size
        int max_buf = LINUX_MAX_SOCKET_SIZE;
        adb_setsockopt(s[0], SOL_SOCKET, SO_SNDBUF, &max_buf, sizeof(max_buf));
        adb_setsockopt(s[1], SOL_SOCKET, SO_SNDBUF, &max_buf, sizeof(max_buf));
    }
#endif // !ADB_HOST

    std::thread(service_bootstrap_func, service_name, func, unique_fd(s[1])).detach();

    D("service thread started, %d:%d",s[0], s[1]);
    return unique_fd(s[0]);
}

int service_to_fd(std::string_view name, atransport* transport) {
    unique_fd ret;

    if (is_socket_spec(name)) {
        std::string error;
        if (!socket_spec_connect(&ret, name, nullptr, nullptr, &error)) {
            LOG(ERROR) << "failed to connect to socket '" << name << "': " << error;
        }
    } else {
#if !ADB_HOST
        ret = daemon_service_to_fd(name, transport);
#endif
    }

    if (ret >= 0) {
        close_on_exec(ret);
    }
    return ret.release();
}

#if ADB_HOST
struct state_info {
    TransportType transport_type;
    std::string serial;
    TransportId transport_id;
    ConnectionState state;
};

static void wait_for_state(int fd, void* data) {
    std::unique_ptr<state_info> sinfo(reinterpret_cast<state_info*>(data));

    D("wait_for_state %d", sinfo->state);

    while (true) {
        bool is_ambiguous = false;
        std::string error = "unknown error";
        const char* serial = sinfo->serial.length() ? sinfo->serial.c_str() : nullptr;
        atransport* t = acquire_one_transport(sinfo->transport_type, serial, sinfo->transport_id,
                                              &is_ambiguous, &error);
        if (t != nullptr && (sinfo->state == kCsAny || sinfo->state == t->GetConnectionState())) {
            SendOkay(fd);
            break;
        } else if (!is_ambiguous) {
            adb_pollfd pfd = {.fd = fd, .events = POLLIN };
            int rc = adb_poll(&pfd, 1, 1000);
            if (rc < 0) {
                SendFail(fd, error);
                break;
            } else if (rc > 0 && (pfd.revents & POLLHUP) != 0) {
                // The other end of the socket is closed, probably because the other side was
                // terminated, bail out.
                break;
            }

            // Try again...
        } else {
            SendFail(fd, error);
            break;
        }
    }

    adb_close(fd);
    D("wait_for_state is done");
}

void connect_emulator(const std::string& port_spec, std::string* response) {
    std::vector<std::string> pieces = android::base::Split(port_spec, ",");
    if (pieces.size() != 2) {
        *response = android::base::StringPrintf("unable to parse '%s' as <console port>,<adb port>",
                                                port_spec.c_str());
        return;
    }

    int console_port = strtol(pieces[0].c_str(), nullptr, 0);
    int adb_port = strtol(pieces[1].c_str(), nullptr, 0);
    if (console_port <= 0 || adb_port <= 0) {
        *response = android::base::StringPrintf("Invalid port numbers: %s", port_spec.c_str());
        return;
    }

    // Check if the emulator is already known.
    // Note: There's a small but harmless race condition here: An emulator not
    // present just yet could be registered by another invocation right
    // after doing this check here. However, local_connect protects
    // against double-registration too. From here, a better error message
    // can be produced. In the case of the race condition, the very specific
    // error message won't be shown, but the data doesn't get corrupted.
    atransport* known_emulator = find_emulator_transport_by_adb_port(adb_port);
    if (known_emulator != nullptr) {
        *response = android::base::StringPrintf("Emulator already registered on port %d", adb_port);
        return;
    }

    // Preconditions met, try to connect to the emulator.
    std::string error;
    if (!local_connect_arbitrary_ports(console_port, adb_port, &error)) {
        *response = android::base::StringPrintf("Connected to emulator on ports %d,%d",
                                                console_port, adb_port);
    } else {
        *response = android::base::StringPrintf("Could not connect to emulator on ports %d,%d: %s",
                                                console_port, adb_port, error.c_str());
    }
}

static void connect_service(unique_fd fd, std::string host) {
    std::string response;
    if (!strncmp(host.c_str(), "emu:", 4)) {
        connect_emulator(host.c_str() + 4, &response);
    } else {
        connect_device(host.c_str(), &response);
    }

    // Send response for emulator and device
    SendProtocolString(fd.get(), response);
}
#endif

#if ADB_HOST
asocket* host_service_to_socket(const char* name, const char* serial, TransportId transport_id) {
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker(false);
    } else if (!strcmp(name, "track-devices-l")) {
        return create_device_tracker(true);
    } else if (android::base::StartsWith(name, "wait-for-")) {
        name += strlen("wait-for-");

        std::unique_ptr<state_info> sinfo = std::make_unique<state_info>();
        if (sinfo == nullptr) {
            fprintf(stderr, "couldn't allocate state_info: %s", strerror(errno));
            return nullptr;
        }

        if (serial) sinfo->serial = serial;
        sinfo->transport_id = transport_id;

        if (android::base::StartsWith(name, "local")) {
            name += strlen("local");
            sinfo->transport_type = kTransportLocal;
        } else if (android::base::StartsWith(name, "usb")) {
            name += strlen("usb");
            sinfo->transport_type = kTransportUsb;
        } else if (android::base::StartsWith(name, "any")) {
            name += strlen("any");
            sinfo->transport_type = kTransportAny;
        } else {
            return nullptr;
        }

        if (!strcmp(name, "-device")) {
            sinfo->state = kCsDevice;
        } else if (!strcmp(name, "-recovery")) {
            sinfo->state = kCsRecovery;
        } else if (!strcmp(name, "-sideload")) {
            sinfo->state = kCsSideload;
        } else if (!strcmp(name, "-bootloader")) {
            sinfo->state = kCsBootloader;
        } else if (!strcmp(name, "-any")) {
            sinfo->state = kCsAny;
        } else {
            return nullptr;
        }

        int fd = create_service_thread(
                         "wait", std::bind(wait_for_state, std::placeholders::_1, sinfo.get()))
                         .release();
        if (fd != -1) {
            sinfo.release();
        }
        return create_local_socket(fd);
    } else if (!strncmp(name, "connect:", 8)) {
        std::string host(name + strlen("connect:"));
        int fd = create_service_thread("connect",
                                       std::bind(connect_service, std::placeholders::_1, host))
                         .release();
        return create_local_socket(fd);
    }
    return nullptr;
}
#endif /* ADB_HOST */
