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
#include "sysdeps/chrono.h"
#include "sysdeps/memory.h"

#if ADB_HOST

// Android Wear has been using port 5601 in all of its documentation/tooling,
// but we search for emulators on ports [5554, 5555 + ADB_LOCAL_TRANSPORT_MAX].
// Avoid stomping on their port by limiting the number of emulators that can be
// connected.
#define ADB_LOCAL_TRANSPORT_MAX 16

static std::mutex& local_transports_lock = *new std::mutex();

// We keep a map from emulator port to transport.
// TODO: weak_ptr?
static auto& local_transports GUARDED_BY(local_transports_lock) =
    *new std::unordered_map<int, atransport*>();
#endif /* ADB_HOST */

bool local_connect(int port) {
    std::string dummy;
    return local_connect_arbitrary_ports(port - 1, port, &dummy) == 0;
}

void connect_device(const std::string& address, std::string* response) {
    if (address.empty()) {
        *response = "empty address";
        return;
    }

    std::string serial;
    std::string host;
    int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    if (!android::base::ParseNetAddress(address, &host, &port, &serial, response)) {
        return;
    }

    std::string error;
    int fd = network_connect(host.c_str(), port, SOCK_STREAM, 10, &error);
    if (fd == -1) {
        *response = android::base::StringPrintf("unable to connect to %s: %s",
                                                serial.c_str(), error.c_str());
        return;
    }

    D("client: connected %s remote on fd %d", serial.c_str(), fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);

    // Send a TCP keepalive ping to the device every second so we can detect disconnects.
    if (!set_tcp_keepalive(fd, 1)) {
        D("warning: failed to configure TCP keepalives (%s)", strerror(errno));
    }

    int ret = register_socket_transport(fd, serial.c_str(), port, 0);
    if (ret < 0) {
        adb_close(fd);
        if (ret == -EALREADY) {
            *response = android::base::StringPrintf("already connected to %s", serial.c_str());
        } else {
            *response = android::base::StringPrintf("failed to connect to %s", serial.c_str());
        }
    } else {
        *response = android::base::StringPrintf("connected to %s", serial.c_str());
    }
}


int local_connect_arbitrary_ports(int console_port, int adb_port, std::string* error) {
    int fd = -1;

#if ADB_HOST
    if (find_emulator_transport_by_adb_port(adb_port) != nullptr ||
        find_emulator_transport_by_console_port(console_port) != nullptr) {
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
        std::string serial = getEmulatorSerialString(console_port);
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
constexpr auto LOCAL_PORT_RETRY_INTERVAL = 1s;

struct RetryPort {
    int port;
    uint32_t retry_count;
};

// Retry emulators just kicked.
static std::vector<RetryPort>& retry_ports = *new std::vector<RetryPort>;
std::mutex &retry_ports_lock = *new std::mutex;
std::condition_variable &retry_ports_cond = *new std::condition_variable;

static void client_socket_thread(int) {
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
        std::this_thread::sleep_for(LOCAL_PORT_RETRY_INTERVAL);

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

static void server_socket_thread(int port) {
    int serverfd, fd;

    adb_thread_setname("server socket");
    D("transport: server_socket_thread() starting");
    serverfd = -1;
    for(;;) {
        if(serverfd == -1) {
            std::string error;
            serverfd = network_inaddr_any_server(port, SOCK_STREAM, &error);
            if(serverfd < 0) {
                D("server: cannot bind socket yet: %s", error.c_str());
                std::this_thread::sleep_for(1s);
                continue;
            }
            close_on_exec(serverfd);
        }

        D("server: trying to get new connection from %d", port);
        fd = adb_socket_accept(serverfd, nullptr, nullptr);
        if(fd >= 0) {
            D("server: new connection on fd %d", fd);
            close_on_exec(fd);
            disable_tcp_nagle(fd);
            std::string serial = android::base::StringPrintf("host-%d", fd);
            if (register_socket_transport(fd, serial.c_str(), port, 1) != 0) {
                adb_close(fd);
            }
        }
    }
    D("transport: server_socket_thread() exiting");
}

/* This is relevant only for ADB daemon running inside the emulator. */
/*
 * Redefine open and write for qemu_pipe.h that contains inlined references
 * to those routines. We will redefine them back after qemu_pipe.h inclusion.
 */
#undef open
#undef read
#undef write
#define open    adb_open
#define read    adb_read
#define write   adb_write
#include <qemu_pipe.h>
#undef open
#undef read
#undef write
#define open    ___xxx_open
#define read    ___xxx_read
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
static void qemu_socket_thread(int port) {
    /* 'accept' request to the adb QEMUD service. */
    static const char _accept_req[] = "accept";
    /* 'start' request to the adb QEMUD service. */
    static const char _start_req[] = "start";
    /* 'ok' reply from the adb QEMUD service. */
    static const char _ok_resp[] = "ok";

    int fd;
    char tmp[256];
    char con_name[32];

    adb_thread_setname("qemu socket");
    D("transport: qemu_socket_thread() starting");

    /* adb QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "pipe:qemud:adb:%d", port);

    /* Connect to the adb QEMUD service. */
    fd = qemu_pipe_open(con_name);
    if (fd < 0) {
        /* This could be an older version of the emulator, that doesn't
         * implement adb QEMUD service. Fall back to the old TCP way. */
        D("adb service is not available. Falling back to TCP socket.");
        std::thread(server_socket_thread, port).detach();
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

// If adbd is running inside the emulator, it will normally use QEMUD pipe (aka
// goldfish) as the transport. This can either be explicitly set by the
// service.adb.transport property, or be inferred from ro.kernel.qemu that is
// set to "1" for ranchu/goldfish.
static bool use_qemu_goldfish() {
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

#endif  // !ADB_HOST

void local_init(int port)
{
    void (*func)(int);
    const char* debug_name = "";

#if ADB_HOST
    func = client_socket_thread;
    debug_name = "client";
#else
    // For the adbd daemon in the system image we need to distinguish
    // between the device, and the emulator.
    func = use_qemu_goldfish() ? qemu_socket_thread : server_socket_thread;
    debug_name = "server";
#endif // !ADB_HOST

    D("transport: local %s init", debug_name);
    std::thread(func, port).detach();
}

#if ADB_HOST
struct EmulatorConnection : public FdConnection {
    EmulatorConnection(unique_fd fd, int local_port)
        : FdConnection(std::move(fd)), local_port_(local_port) {}

    ~EmulatorConnection() {
        VLOG(TRANSPORT) << "remote_close, local_port = " << local_port_;
        std::unique_lock<std::mutex> lock(retry_ports_lock);
        RetryPort port;
        port.port = local_port_;
        port.retry_count = LOCAL_PORT_RETRY_COUNT;
        retry_ports.push_back(port);
        retry_ports_cond.notify_one();
    }

    void Close() override {
        std::lock_guard<std::mutex> lock(local_transports_lock);
        local_transports.erase(local_port_);
        FdConnection::Close();
    }

    int local_port_;
};

/* Only call this function if you already hold local_transports_lock. */
static atransport* find_emulator_transport_by_adb_port_locked(int adb_port)
    REQUIRES(local_transports_lock) {
    auto it = local_transports.find(adb_port);
    if (it == local_transports.end()) {
        return nullptr;
    }
    return it->second;
}

std::string getEmulatorSerialString(int console_port) {
    return android::base::StringPrintf("emulator-%d", console_port);
}

atransport* find_emulator_transport_by_adb_port(int adb_port) {
    std::lock_guard<std::mutex> lock(local_transports_lock);
    return find_emulator_transport_by_adb_port_locked(adb_port);
}

atransport* find_emulator_transport_by_console_port(int console_port) {
    return find_transport(getEmulatorSerialString(console_port).c_str());
}
#endif

int init_socket_transport(atransport* t, int s, int adb_port, int local) {
    int fail = 0;

    unique_fd fd(s);
    t->type = kTransportLocal;

#if ADB_HOST
    // Emulator connection.
    if (local) {
        auto emulator_connection = std::make_unique<EmulatorConnection>(std::move(fd), adb_port);
        t->SetConnection(
            std::make_unique<BlockingConnectionAdapter>(std::move(emulator_connection)));
        std::lock_guard<std::mutex> lock(local_transports_lock);
        atransport* existing_transport = find_emulator_transport_by_adb_port_locked(adb_port);
        if (existing_transport != NULL) {
            D("local transport for port %d already registered (%p)?", adb_port, existing_transport);
            fail = -1;
        } else if (local_transports.size() >= ADB_LOCAL_TRANSPORT_MAX) {
            // Too many emulators.
            D("cannot register more emulators. Maximum is %d", ADB_LOCAL_TRANSPORT_MAX);
            fail = -1;
        } else {
            local_transports[adb_port] = t;
        }

        return fail;
    }
#endif

    // Regular tcp connection.
    auto fd_connection = std::make_unique<FdConnection>(std::move(fd));
    t->SetConnection(std::make_unique<BlockingConnectionAdapter>(std::move(fd_connection)));
    return fail;
}
