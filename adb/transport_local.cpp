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
#include "sysdeps/condition_variable.h"
#include "sysdeps/mutex.h"
#include "transport.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <vector>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>

#if !ADB_HOST
#include "cutils/properties.h"
#endif

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"

#if ADB_HOST
/* we keep a list of opened transports. The atransport struct knows to which
 * local transport it is connected. The list is used to detect when we're
 * trying to connect twice to a given local transport.
 */
#define  ADB_LOCAL_TRANSPORT_MAX  64

ADB_MUTEX_DEFINE( local_transports_lock );

static atransport*  local_transports[ ADB_LOCAL_TRANSPORT_MAX ];
#endif /* ADB_HOST */

static int remote_read(apacket *p, atransport *t)
{
    if(!ReadFdExactly(t->sfd, &p->msg, sizeof(amessage))){
        D("remote local: read terminated (message)");
        return -1;
    }

    if(check_header(p, t)) {
        D("bad header: terminated (data)");
        return -1;
    }

    if(!ReadFdExactly(t->sfd, p->data, p->msg.data_length)){
        D("remote local: terminated (data)");
        return -1;
    }

    if(check_data(p)) {
        D("bad data: terminated (data)");
        return -1;
    }

    return 0;
}

static int remote_write(apacket *p, atransport *t)
{
    int   length = p->msg.data_length;

    if(!WriteFdExactly(t->sfd, &p->msg, sizeof(amessage) + length)) {
        D("remote local: write terminated");
        return -1;
    }

    return 0;
}

bool local_connect(int port) {
    std::string dummy;
    return local_connect_arbitrary_ports(port-1, port, &dummy) == 0;
}

int local_connect_arbitrary_ports(int console_port, int adb_port, std::string* error) {
    int fd = -1;

#if ADB_HOST
    if (find_emulator_transport_by_adb_port(adb_port) != nullptr) {
        return -1;
    }

    const char *host = getenv("ADBHOST");
    if (host) {
        fd = network_connect(host, adb_port, SOCK_STREAM, 0, error);
    }
#endif
    if (fd < 0) {
        fd = network_loopback_client(adb_port, SOCK_STREAM, error);
    }

    if (fd >= 0) {
        D("client: connected on remote on fd %d", fd);
        close_on_exec(fd);
        disable_tcp_nagle(fd);
        std::string serial = android::base::StringPrintf("emulator-%d", console_port);
        if (register_socket_transport(fd, serial.c_str(), adb_port, 1) == 0) {
            return 0;
        }
        adb_close(fd);
    }
    return -1;
}

#if ADB_HOST

static void PollAllLocalPortsForEmulator() {
    int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    int count = ADB_LOCAL_TRANSPORT_MAX;

    // Try to connect to any number of running emulator instances.
    for ( ; count > 0; count--, port += 2 ) {
        local_connect(port);
    }
}

// Retry the disconnected local port for 60 times, and sleep 1 second between two retries.
constexpr uint32_t LOCAL_PORT_RETRY_COUNT = 60;
constexpr uint32_t LOCAL_PORT_RETRY_INTERVAL_IN_MS = 1000;

struct RetryPort {
    int port;
    uint32_t retry_count;
};

// Retry emulators just kicked.
static std::vector<RetryPort>& retry_ports = *new std::vector<RetryPort>;
std::mutex &retry_ports_lock = *new std::mutex;
std::condition_variable &retry_ports_cond = *new std::condition_variable;

static void client_socket_thread(void* x) {
    adb_thread_setname("client_socket_thread");
    D("transport: client_socket_thread() starting");
    PollAllLocalPortsForEmulator();
    while (true) {
        std::vector<RetryPort> ports;
        // Collect retry ports.
        {
            std::unique_lock<std::mutex> lock(retry_ports_lock);
            while (retry_ports.empty()) {
                retry_ports_cond.wait(lock);
            }
            retry_ports.swap(ports);
        }
        // Sleep here instead of the end of loop, because if we immediately try to reconnect
        // the emulator just kicked, the adbd on the emulator may not have time to remove the
        // just kicked transport.
        adb_sleep_ms(LOCAL_PORT_RETRY_INTERVAL_IN_MS);

        // Try connecting retry ports.
        std::vector<RetryPort> next_ports;
        for (auto& port : ports) {
            VLOG(TRANSPORT) << "retry port " << port.port << ", last retry_count "
                << port.retry_count;
            if (local_connect(port.port)) {
                VLOG(TRANSPORT) << "retry port " << port.port << " successfully";
                continue;
            }
            if (--port.retry_count > 0) {
                next_ports.push_back(port);
            } else {
                VLOG(TRANSPORT) << "stop retrying port " << port.port;
            }
        }

        // Copy back left retry ports.
        {
            std::unique_lock<std::mutex> lock(retry_ports_lock);
            retry_ports.insert(retry_ports.end(), next_ports.begin(), next_ports.end());
        }
    }
}

#else // ADB_HOST

static void server_socket_thread(void* arg) {
    int serverfd, fd;
    sockaddr_storage ss;
    sockaddr *addrp = reinterpret_cast<sockaddr*>(&ss);
    socklen_t alen;
    int port = (int) (uintptr_t) arg;

    adb_thread_setname("server socket");
    D("transport: server_socket_thread() starting");
    serverfd = -1;
    for(;;) {
        if(serverfd == -1) {
            std::string error;
            serverfd = network_inaddr_any_server(port, SOCK_STREAM, &error);
            if(serverfd < 0) {
                D("server: cannot bind socket yet: %s", error.c_str());
                adb_sleep_ms(1000);
                continue;
            }
            close_on_exec(serverfd);
        }

        alen = sizeof(ss);
        D("server: trying to get new connection from %d", port);
        fd = adb_socket_accept(serverfd, addrp, &alen);
        if(fd >= 0) {
            D("server: new connection on fd %d", fd);
            close_on_exec(fd);
            disable_tcp_nagle(fd);
            if (register_socket_transport(fd, "host", port, 1) != 0) {
                adb_close(fd);
            }
        }
    }
    D("transport: server_socket_thread() exiting");
}

/* This is relevant only for ADB daemon running inside the emulator. */
/*
 * Redefine open and write for qemu_pipe.h that contains inlined references
 * to those routines. We will redifine them back after qemu_pipe.h inclusion.
 */
#undef open
#undef write
#define open    adb_open
#define write   adb_write
#include <hardware/qemu_pipe.h>
#undef open
#undef write
#define open    ___xxx_open
#define write   ___xxx_write

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
static void qemu_socket_thread(void* arg) {
    /* 'accept' request to the adb QEMUD service. */
    static const char _accept_req[] = "accept";
    /* 'start' request to the adb QEMUD service. */
    static const char _start_req[] = "start";
    /* 'ok' reply from the adb QEMUD service. */
    static const char _ok_resp[] = "ok";

    const int port = (int) (uintptr_t) arg;
    int fd;
    char tmp[256];
    char con_name[32];

    adb_thread_setname("qemu socket");
    D("transport: qemu_socket_thread() starting");

    /* adb QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "qemud:adb:%d", port);

    /* Connect to the adb QEMUD service. */
    fd = qemu_pipe_open(con_name);
    if (fd < 0) {
        /* This could be an older version of the emulator, that doesn't
         * implement adb QEMUD service. Fall back to the old TCP way. */
        D("adb service is not available. Falling back to TCP socket.");
        adb_thread_create(server_socket_thread, arg);
        return;
    }

    for(;;) {
        /*
         * Wait till the host creates a new connection.
         */

        /* Send the 'accept' request. */
        if (WriteFdExactly(fd, _accept_req, strlen(_accept_req))) {
            /* Wait for the response. In the response we expect 'ok' on success,
             * or 'ko' on failure. */
            if (!ReadFdExactly(fd, tmp, 2) || memcmp(tmp, _ok_resp, 2)) {
                D("Accepting ADB host connection has failed.");
                adb_close(fd);
            } else {
                /* Host is connected. Register the transport, and start the
                 * exchange. */
                std::string serial = android::base::StringPrintf("host-%d", fd);
                if (register_socket_transport(fd, serial.c_str(), port, 1) != 0 ||
                    !WriteFdExactly(fd, _start_req, strlen(_start_req))) {
                    adb_close(fd);
                }
            }

            /* Prepare for accepting of the next ADB host connection. */
            fd = qemu_pipe_open(con_name);
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
#endif  // !ADB_HOST

void local_init(int port)
{
    adb_thread_func_t func;
    const char* debug_name = "";

#if ADB_HOST
    func = client_socket_thread;
    debug_name = "client";
#else
    /* For the adbd daemon in the system image we need to distinguish
     * between the device, and the emulator. */
    char is_qemu[PROPERTY_VALUE_MAX];
    property_get("ro.kernel.qemu", is_qemu, "");
    if (!strcmp(is_qemu, "1")) {
        /* Running inside the emulator: use QEMUD pipe as the transport. */
        func = qemu_socket_thread;
    } else {
        /* Running inside the device: use TCP socket as the transport. */
        func = server_socket_thread;
    }
    debug_name = "server";
#endif // !ADB_HOST

    D("transport: local %s init", debug_name);
    if (!adb_thread_create(func, (void *) (uintptr_t) port)) {
        fatal_errno("cannot create local socket %s thread", debug_name);
    }
}

static void remote_kick(atransport *t)
{
    int fd = t->sfd;
    t->sfd = -1;
    adb_shutdown(fd);
    adb_close(fd);

#if ADB_HOST
    int  nn;
    adb_mutex_lock( &local_transports_lock );
    for (nn = 0; nn < ADB_LOCAL_TRANSPORT_MAX; nn++) {
        if (local_transports[nn] == t) {
            local_transports[nn] = NULL;
            break;
        }
    }
    adb_mutex_unlock( &local_transports_lock );
#endif
}

static void remote_close(atransport *t)
{
    int fd = t->sfd;
    if (fd != -1) {
        t->sfd = -1;
        adb_close(fd);
    }
#if ADB_HOST
    int local_port;
    if (t->GetLocalPortForEmulator(&local_port)) {
        VLOG(TRANSPORT) << "remote_close, local_port = " << local_port;
        std::unique_lock<std::mutex> lock(retry_ports_lock);
        RetryPort port;
        port.port = local_port;
        port.retry_count = LOCAL_PORT_RETRY_COUNT;
        retry_ports.push_back(port);
        retry_ports_cond.notify_one();
    }
#endif
}


#if ADB_HOST
/* Only call this function if you already hold local_transports_lock. */
static atransport* find_emulator_transport_by_adb_port_locked(int adb_port)
{
    int i;
    for (i = 0; i < ADB_LOCAL_TRANSPORT_MAX; i++) {
        int local_port;
        if (local_transports[i] && local_transports[i]->GetLocalPortForEmulator(&local_port)) {
            if (local_port == adb_port) {
                return local_transports[i];
            }
        }
    }
    return NULL;
}

atransport* find_emulator_transport_by_adb_port(int adb_port)
{
    adb_mutex_lock( &local_transports_lock );
    atransport* result = find_emulator_transport_by_adb_port_locked(adb_port);
    adb_mutex_unlock( &local_transports_lock );
    return result;
}

/* Only call this function if you already hold local_transports_lock. */
int get_available_local_transport_index_locked()
{
    int i;
    for (i = 0; i < ADB_LOCAL_TRANSPORT_MAX; i++) {
        if (local_transports[i] == NULL) {
            return i;
        }
    }
    return -1;
}

int get_available_local_transport_index()
{
    adb_mutex_lock( &local_transports_lock );
    int result = get_available_local_transport_index_locked();
    adb_mutex_unlock( &local_transports_lock );
    return result;
}
#endif

int init_socket_transport(atransport *t, int s, int adb_port, int local)
{
    int  fail = 0;

    t->SetKickFunction(remote_kick);
    t->close = remote_close;
    t->read_from_remote = remote_read;
    t->write_to_remote = remote_write;
    t->sfd = s;
    t->sync_token = 1;
    t->connection_state = kCsOffline;
    t->type = kTransportLocal;

#if ADB_HOST
    if (local) {
        adb_mutex_lock( &local_transports_lock );
        {
            t->SetLocalPortForEmulator(adb_port);
            atransport* existing_transport =
                    find_emulator_transport_by_adb_port_locked(adb_port);
            int index = get_available_local_transport_index_locked();
            if (existing_transport != NULL) {
                D("local transport for port %d already registered (%p)?",
                adb_port, existing_transport);
                fail = -1;
            } else if (index < 0) {
                // Too many emulators.
                D("cannot register more emulators. Maximum is %d",
                        ADB_LOCAL_TRANSPORT_MAX);
                fail = -1;
            } else {
                local_transports[index] = t;
            }
       }
       adb_mutex_unlock( &local_transports_lock );
    }
#endif
    return fail;
}
