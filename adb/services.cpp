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

#include <cstring>
#include <thread>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "adb_wifi.h"
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
#endif  // !ADB_HOST

    std::thread(service_bootstrap_func, service_name, func, unique_fd(s[1])).detach();

    D("service thread started, %d:%d", s[0], s[1]);
    return unique_fd(s[0]);
}

unique_fd service_to_fd(std::string_view name, atransport* transport) {
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
        close_on_exec(ret.get());
    }
    return ret;
}

#if ADB_HOST
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
        connect_device(host, &response);
    }

    // Send response for emulator and device
    SendProtocolString(fd.get(), response);
}

static void pair_service(unique_fd fd, std::string host, std::string password) {
    std::string response;
    adb_wifi_pair_device(host, password, response);
    SendProtocolString(fd.get(), response);
}

static void wait_service(unique_fd fd, std::string serial, TransportId transport_id,
                         std::string spec) {
    std::vector<std::string> components = android::base::Split(spec, "-");
    if (components.size() < 2) {
        SendFail(fd, "short wait-for-: " + spec);
        return;
    }

    TransportType transport_type;
    if (components[0] == "local") {
        transport_type = kTransportLocal;
    } else if (components[0] == "usb") {
        transport_type = kTransportUsb;
    } else if (components[0] == "any") {
        transport_type = kTransportAny;
    } else {
        SendFail(fd, "bad wait-for- transport: " + spec);
        return;
    }

    std::vector<ConnectionState> states;
    for (size_t i = 1; i < components.size(); ++i) {
        if (components[i] == "device") {
            states.push_back(kCsDevice);
        } else if (components[i] == "recovery") {
            states.push_back(kCsRecovery);
        } else if (components[i] == "rescue") {
            states.push_back(kCsRescue);
        } else if (components[i] == "sideload") {
            states.push_back(kCsSideload);
        } else if (components[i] == "bootloader") {
            states.push_back(kCsBootloader);
        } else if (components[i] == "any") {
            states.push_back(kCsAny);
        } else if (components[i] == "disconnect") {
            states.push_back(kCsOffline);
        } else {
            SendFail(fd, "bad wait-for- state: " + spec);
            return;
        }
    }

    while (true) {
        bool is_ambiguous = false;
        std::string error = "unknown error";
        atransport* t =
                acquire_one_transport(transport_type, !serial.empty() ? serial.c_str() : nullptr,
                                      transport_id, &is_ambiguous, &error);

        for (const auto& state : states) {
            if (state == kCsOffline) {
                // Special case for wait-for-disconnect:
                // We want to wait for USB devices to completely disappear, but TCP devices can
                // go into the offline state, since we automatically reconnect.
                if (!t) {
                    SendOkay(fd);
                    return;
                } else if (!t->GetUsbHandle()) {
                    SendOkay(fd);
                    return;
                }
            } else {
                if (t && (state == kCsAny || state == t->GetConnectionState())) {
                    SendOkay(fd);
                    return;
                }
            }
        }

        if (is_ambiguous) {
            SendFail(fd, error);
            return;
        }

        // Sleep before retrying.
        adb_pollfd pfd = {.fd = fd.get(), .events = POLLIN};
        if (adb_poll(&pfd, 1, 100) != 0) {
            // The other end of the socket is closed, probably because the
            // client terminated. Bail out.
            SendFail(fd, error);
            return;
        }
    }
}
#endif

#if ADB_HOST
asocket* host_service_to_socket(std::string_view name, std::string_view serial,
                                TransportId transport_id) {
    if (name == "track-devices") {
        return create_device_tracker(false);
    } else if (name == "track-devices-l") {
        return create_device_tracker(true);
    } else if (android::base::ConsumePrefix(&name, "wait-for-")) {
        std::string spec(name);
        unique_fd fd =
                create_service_thread("wait", std::bind(wait_service, std::placeholders::_1,
                                                        std::string(serial), transport_id, spec));
        return create_local_socket(std::move(fd));
    } else if (android::base::ConsumePrefix(&name, "connect:")) {
        std::string host(name);
        unique_fd fd = create_service_thread(
                "connect", std::bind(connect_service, std::placeholders::_1, host));
        return create_local_socket(std::move(fd));
    } else if (android::base::ConsumePrefix(&name, "pair:")) {
        const char* divider = strchr(name.data(), ':');
        if (!divider) {
            return nullptr;
        }
        std::string password(name.data(), divider);
        std::string host(divider + 1);
        unique_fd fd = create_service_thread(
                "pair", std::bind(pair_service, std::placeholders::_1, host, password));
        return create_local_socket(std::move(fd));
    }
    return nullptr;
}
#endif /* ADB_HOST */
