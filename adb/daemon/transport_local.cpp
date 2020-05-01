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

#define TRACE_TAG TRANSPORT

#include "sysdeps.h"
#include "transport.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/thread_annotations.h>
#include <cutils/sockets.h>

#if !ADB_HOST
#include <android-base/properties.h>
#endif

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "socket_spec.h"
#include "sysdeps/chrono.h"

void server_socket_thread(std::function<unique_fd(std::string_view, std::string*)> listen_func,
                          std::string_view addr) {
    adb_thread_setname("server socket");

    unique_fd serverfd;
    std::string error;

    while (serverfd == -1) {
        errno = 0;
        serverfd = listen_func(addr, &error);
        if (errno == EAFNOSUPPORT || errno == EINVAL || errno == EPROTONOSUPPORT) {
            D("unrecoverable error: '%s'", error.c_str());
            return;
        } else if (serverfd < 0) {
            D("server: cannot bind socket yet: %s", error.c_str());
            std::this_thread::sleep_for(1s);
            continue;
        }
        close_on_exec(serverfd.get());
    }

    while (true) {
        D("server: trying to get new connection from fd %d", serverfd.get());
        unique_fd fd(adb_socket_accept(serverfd, nullptr, nullptr));
        if (fd >= 0) {
            D("server: new connection on fd %d", fd.get());
            close_on_exec(fd.get());
            disable_tcp_nagle(fd.get());
            std::string serial = android::base::StringPrintf("host-%d", fd.get());
            // We don't care about port value in "register_socket_transport" as it is used
            // only from ADB_HOST. "server_socket_thread" is never called from ADB_HOST.
            register_socket_transport(
                    std::move(fd), std::move(serial), 0, 1,
                    [](atransport*) { return ReconnectResult::Abort; }, false);
        }
    }
    D("transport: server_socket_thread() exiting");
}

unique_fd adb_listen(std::string_view addr, std::string* error) {
    return unique_fd{socket_spec_listen(addr, error, nullptr)};
}

void local_init(const std::string& addr) {
#if !defined(__ANDROID__)
    // Host adbd.
    D("transport: local server init");
    std::thread(server_socket_thread, adb_listen, addr).detach();
#else
    D("transport: local server init");
    // For the adbd daemon in the system image we need to distinguish
    // between the device, and the emulator.
    if (addr.starts_with("tcp:") && use_qemu_goldfish()) {
        std::thread(qemu_socket_thread, addr).detach();
    } else {
        std::thread(server_socket_thread, adb_listen, addr).detach();
    }
#endif  // !ADB_HOST
}

int init_socket_transport(atransport* t, unique_fd fd, int adb_port, int local) {
    t->type = kTransportLocal;
    auto fd_connection = std::make_unique<FdConnection>(std::move(fd));
    t->SetConnection(std::make_unique<BlockingConnectionAdapter>(std::move(fd_connection)));
    return 0;
}
