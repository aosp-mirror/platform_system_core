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

// Include qemu_pipe.h before sysdeps, since it has inlined references to open, read, write.
#include <qemu_pipe.h>

#define TRACE_TAG TRANSPORT
#include "sysdeps.h"
#include "transport.h"

#include <android-base/properties.h>

#include "adb_io.h"
#include "adb_trace.h"
#include "adb_unique_fd.h"

/* A worker thread that monitors host connections, and registers a transport for
 * every new host connection. This thread replaces server_socket_thread on
 * condition that adbd daemon runs inside the emulator, and emulator uses QEMUD
 * pipe to communicate with adbd daemon inside the guest. This is done in order
 * to provide more robust communication channel between ADB host and guest. The
 * main issue with server_socket_thread approach is that it runs on top of TCP,
 * and thus is sensitive to network disruptions. For instance, the
 * ConnectionManager may decide to reset all network connections, in which case
 * the connection between ADB host and guest will be lost. To make ADB traffic
 * independent from the network, we use here 'adb' QEMUD service to transfer data
 * between the host, and the guest. See external/qemu/android/adb-*.* that
 * implements the emulator's side of the protocol. Another advantage of using
 * QEMUD approach is that ADB will be up much sooner, since it doesn't depend
 * anymore on network being set up.
 * The guest side of the protocol contains the following phases:
 * - Connect with adb QEMUD service. In this phase a handle to 'adb' QEMUD service
 *   is opened, and it becomes clear whether or not emulator supports that
 *   protocol.
 * - Wait for the ADB host to create connection with the guest. This is done by
 *   sending an 'accept' request to the adb QEMUD service, and waiting on
 *   response.
 * - When new ADB host connection is accepted, the connection with adb QEMUD
 *   service is registered as the transport, and a 'start' request is sent to the
 *   adb QEMUD service, indicating that the guest is ready to receive messages.
 *   Note that the guest will ignore messages sent down from the emulator before
 *   the transport registration is completed. That's why we need to send the
 *   'start' request after the transport is registered.
 */
void qemu_socket_thread(int port) {
    /* 'accept' request to the adb QEMUD service. */
    static const char _accept_req[] = "accept";
    /* 'start' request to the adb QEMUD service. */
    static const char _start_req[] = "start";
    /* 'ok' reply from the adb QEMUD service. */
    static const char _ok_resp[] = "ok";

    char tmp[256];
    char con_name[32];

    adb_thread_setname("qemu socket");
    D("transport: qemu_socket_thread() starting");

    /* adb QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "pipe:qemud:adb:%d", port);

    /* Connect to the adb QEMUD service. */
    unique_fd fd(qemu_pipe_open(con_name));
    if (fd < 0) {
        /* This could be an older version of the emulator, that doesn't
         * implement adb QEMUD service. Fall back to the old TCP way. */
        D("adb service is not available. Falling back to TCP socket.");
        std::thread(server_socket_thread, tcp_listen_inaddr_any, port).detach();
        return;
    }

    while (true) {
        /*
         * Wait till the host creates a new connection.
         */

        /* Send the 'accept' request. */
        if (WriteFdExactly(fd.get(), _accept_req, strlen(_accept_req))) {
            /* Wait for the response. In the response we expect 'ok' on success,
             * or 'ko' on failure. */
            if (!ReadFdExactly(fd.get(), tmp, 2) || memcmp(tmp, _ok_resp, 2)) {
                D("Accepting ADB host connection has failed.");
            } else {
                /* Host is connected. Register the transport, and start the
                 * exchange. */
                std::string serial = android::base::StringPrintf("host-%d", fd.get());
                WriteFdExactly(fd.get(), _start_req, strlen(_start_req));
                register_socket_transport(std::move(fd), std::move(serial), port, 1,
                                          [](atransport*) { return ReconnectResult::Abort; });
            }

            /* Prepare for accepting of the next ADB host connection. */
            fd.reset(qemu_pipe_open(con_name));
            if (fd < 0) {
                D("adb service become unavailable.");
                return;
            }
        } else {
            D("Unable to send the '%s' request to ADB service.", _accept_req);
            return;
        }
    }
    D("transport: qemu_socket_thread() exiting");
    return;
}

// If adbd is running inside the emulator, it will normally use QEMUD pipe (aka
// goldfish) as the transport. This can either be explicitly set by the
// service.adb.transport property, or be inferred from ro.kernel.qemu that is
// set to "1" for ranchu/goldfish.
bool use_qemu_goldfish() {
    // Legacy way to detect if adbd should use the goldfish pipe is to check for
    // ro.kernel.qemu, keep that behaviour for backward compatibility.
    if (android::base::GetBoolProperty("ro.kernel.qemu", false)) {
        return true;
    }
    // If service.adb.transport is present and is set to "goldfish", use the
    // QEMUD pipe.
    if (android::base::GetProperty("service.adb.transport", "") == "goldfish") {
        return true;
    }
    return false;
}
