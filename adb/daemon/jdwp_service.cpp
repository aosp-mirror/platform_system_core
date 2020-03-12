/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define TRACE_TAG JDWP

#include "sysdeps.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <list>
#include <memory>
#include <thread>
#include <vector>

#include <adbconnection/process_info.h>
#include <adbconnection/server.h>
#include <android-base/cmsg.h>
#include <android-base/unique_fd.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "app_processes.pb.h"

using android::base::borrowed_fd;
using android::base::unique_fd;

/* here's how these things work.

   when adbd starts, it creates a unix server socket
   named @jdwp-control (@ is a shortcut for "first byte is zero"
   to use the private namespace instead of the file system)

   when a new JDWP daemon thread starts in a new VM process, it creates
   a connection to @jdwp-control to announce its availability.


     JDWP thread                             @jdwp-control
         |                                         |
         |------------------------------->         |
         | hello I'm in process <pid>              |
         |                                         |
         |                                         |

    the connection is kept alive. it will be closed automatically if
    the JDWP process terminates (this allows adbd to detect dead
    processes).

    adbd thus maintains a list of "active" JDWP processes. it can send
    its content to clients through the "device:debug-ports" service,
    or even updates through the "device:track-debug-ports" service.

    when a debugger wants to connect, it simply runs the command
    equivalent to  "adb forward tcp:<hostport> jdwp:<pid>"

    "jdwp:<pid>" is a new forward destination format used to target
    a given JDWP process on the device. when sutch a request arrives,
    adbd does the following:

      - first, it calls socketpair() to create a pair of equivalent
        sockets.

      - it attaches the first socket in the pair to a local socket
        which is itself attached to the transport's remote socket:


      - it sends the file descriptor of the second socket directly
        to the JDWP process with the help of sendmsg()


     JDWP thread                             @jdwp-control
         |                                         |
         |                  <----------------------|
         |           OK, try this file descriptor  |
         |                                         |
         |                                         |

   then, the JDWP thread uses this new socket descriptor as its
   pass-through connection to the debugger (and receives the
   JDWP-Handshake message, answers to it, etc...)

   this gives the following graphics:
                    ____________________________________
                   |                                    |
                   |          ADB Server (host)         |
                   |                                    |
        Debugger <---> LocalSocket <----> RemoteSocket  |
                   |                           ^^       |
                   |___________________________||_______|
                                               ||
                                     Transport ||
           (TCP for emulator - USB for device) ||
                                               ||
                    ___________________________||_______
                   |                           ||       |
                   |          ADBD  (device)   ||       |
                   |                           VV       |
         JDWP <======> LocalSocket <----> RemoteSocket  |
                   |                                    |
                   |____________________________________|

    due to the way adb works, this doesn't need a special socket
    type or fancy handling of socket termination if either the debugger
    or the JDWP process closes the connection.

    THIS IS THE SIMPLEST IMPLEMENTATION I COULD FIND, IF YOU HAPPEN
    TO HAVE A BETTER IDEA, LET ME KNOW - Digit

**********************************************************************/

/** JDWP PID List Support Code
 ** for each JDWP process, we record its pid and its connected socket
 **/

enum class TrackerKind {
    kJdwp,
    kApp,
};

static void jdwp_process_event(int socket, unsigned events, void* _proc);
static void jdwp_process_list_updated(void);
static void app_process_list_updated(void);

struct JdwpProcess;
static auto& _jdwp_list = *new std::list<std::unique_ptr<JdwpProcess>>();

struct JdwpProcess {
    JdwpProcess(unique_fd socket, ProcessInfo process) {
        CHECK(process.pid != 0);

        this->socket = socket;
        this->process = process;
        this->fde = fdevent_create(socket.release(), jdwp_process_event, this);

        if (!this->fde) {
            LOG(FATAL) << "could not create fdevent for new JDWP process";
        }
    }

    ~JdwpProcess() {
        if (this->socket >= 0) {
            adb_shutdown(this->socket);
            this->socket = -1;
        }

        if (this->fde) {
            fdevent_destroy(this->fde);
            this->fde = nullptr;
        }

        out_fds.clear();
    }

    void RemoveFromList() {
        auto pred = [this](const auto& proc) { return proc.get() == this; };
        _jdwp_list.remove_if(pred);
    }

    borrowed_fd socket = -1;
    ProcessInfo process;
    fdevent* fde = nullptr;

    std::vector<unique_fd> out_fds;
};

// Populate the list of processes for "track-jdwp" service.
static size_t jdwp_process_list(char* buffer, size_t bufferlen) {
    std::string temp;

    for (auto& proc : _jdwp_list) {
        if (!proc->process.debuggable) continue;
        std::string next = std::to_string(proc->process.pid) + "\n";
        if (temp.length() + next.length() > bufferlen) {
            D("truncating JDWP process list (max len = %zu)", bufferlen);
            break;
        }
        temp.append(next);
    }

    memcpy(buffer, temp.data(), temp.length());
    return temp.length();
}

// Populate the list of processes for "track-app" service.
// The list is a protobuf message in the binary format for efficiency.
static size_t app_process_list(char* buffer, size_t bufferlen) {
    adb::proto::AppProcesses output;  // result that's guaranteed to fit in the given buffer
    adb::proto::AppProcesses temp;    // temporary result that may be longer than the given buffer
    std::string serialized_message;

    for (auto& proc : _jdwp_list) {
        if (!proc->process.debuggable && !proc->process.profileable) continue;
        auto* entry = temp.add_process();
        entry->set_pid(proc->process.pid);
        entry->set_debuggable(proc->process.debuggable);
        entry->set_profileable(proc->process.profileable);
        entry->set_architecture(proc->process.arch_name, proc->process.arch_name_length);
        temp.SerializeToString(&serialized_message);
        if (serialized_message.size() > bufferlen) {
            D("truncating app process list (max len = %zu)", bufferlen);
            break;
        }
        output = temp;
    }
    output.SerializeToString(&serialized_message);
    memcpy(buffer, serialized_message.data(), serialized_message.length());
    return serialized_message.length();
}

// Populate the list of processes for either "track-jdwp" or "track-app" services,
// depending on the given kind.
static size_t process_list(TrackerKind kind, char* buffer, size_t bufferlen) {
    switch (kind) {
        case TrackerKind::kJdwp:
            return jdwp_process_list(buffer, bufferlen);
        case TrackerKind::kApp:
            return app_process_list(buffer, bufferlen);
    }
}

static size_t process_list_msg(TrackerKind kind, char* buffer, size_t bufferlen) {
    // Message is length-prefixed with 4 hex digits in ASCII.
    static constexpr size_t header_len = 4;
    if (bufferlen < header_len) {
        LOG(FATAL) << "invalid JDWP process list buffer size: " << bufferlen;
    }

    char head[header_len + 1];
    size_t len = process_list(kind, buffer + header_len, bufferlen - header_len);
    snprintf(head, sizeof head, "%04zx", len);
    memcpy(buffer, head, header_len);
    return len + header_len;
}

static void jdwp_process_event(int socket, unsigned events, void* _proc) {
    JdwpProcess* proc = reinterpret_cast<JdwpProcess*>(_proc);
    CHECK_EQ(socket, proc->socket.get());

    if (events & FDE_READ) {
        // We already have the PID, if we can read from the socket, we've probably hit EOF.
        D("terminating JDWP connection %" PRId64, proc->process.pid);
        goto CloseProcess;
    }

    if (events & FDE_WRITE) {
        D("trying to send fd to JDWP process (count = %zu)", proc->out_fds.size());
        CHECK(!proc->out_fds.empty());

        int fd = proc->out_fds.back().get();
        if (android::base::SendFileDescriptors(socket, "", 1, fd) != 1) {
            D("sending new file descriptor to JDWP %" PRId64 " failed: %s", proc->process.pid,
              strerror(errno));
            goto CloseProcess;
        }

        D("sent file descriptor %d to JDWP process %" PRId64, fd, proc->process.pid);

        proc->out_fds.pop_back();
        if (proc->out_fds.empty()) {
            fdevent_del(proc->fde, FDE_WRITE);
        }
    }

    return;

CloseProcess:
    bool debuggable = proc->process.debuggable;
    bool profileable = proc->process.profileable;
    proc->RemoveFromList();
    if (debuggable) jdwp_process_list_updated();
    if (debuggable || profileable) app_process_list_updated();
}

unique_fd create_jdwp_connection_fd(int pid) {
    D("looking for pid %d in JDWP process list", pid);

    for (auto& proc : _jdwp_list) {
        // Don't allow JDWP connection to a non-debuggable process.
        if (!proc->process.debuggable) continue;
        if (proc->process.pid == static_cast<uint64_t>(pid)) {
            int fds[2];

            if (adb_socketpair(fds) < 0) {
                D("%s: socket pair creation failed: %s", __FUNCTION__, strerror(errno));
                return unique_fd{};
            }
            D("socketpair: (%d,%d)", fds[0], fds[1]);

            proc->out_fds.emplace_back(fds[1]);
            if (proc->out_fds.size() == 1) {
                fdevent_add(proc->fde, FDE_WRITE);
            }

            return unique_fd{fds[0]};
        }
    }
    D("search failed !!");
    return unique_fd{};
}

/** "jdwp" local service implementation
 ** this simply returns the list of known JDWP process pids
 **/

struct JdwpSocket : public asocket {
    bool pass = false;
};

static void jdwp_socket_close(asocket* s) {
    D("LS(%d): closing jdwp socket", s->id);

    if (s->peer) {
        D("LS(%d) peer->close()ing peer->id=%d peer->fd=%d", s->id, s->peer->id, s->peer->fd);
        s->peer->peer = nullptr;
        s->peer->close(s->peer);
        s->peer = nullptr;
    }

    remove_socket(s);
    delete s;
}

static int jdwp_socket_enqueue(asocket* s, apacket::payload_type) {
    /* you can't write to this asocket */
    D("LS(%d): JDWP socket received data?", s->id);
    s->peer->close(s->peer);
    return -1;
}

static void jdwp_socket_ready(asocket* s) {
    JdwpSocket* jdwp = (JdwpSocket*)s;
    asocket* peer = jdwp->peer;

    /* on the first call, send the list of pids,
     * on the second one, close the connection
     */
    if (!jdwp->pass) {
        apacket::payload_type data;
        data.resize(s->get_max_payload());
        size_t len = jdwp_process_list(&data[0], data.size());
        data.resize(len);
        peer->enqueue(peer, std::move(data));
        jdwp->pass = true;
    } else {
        peer->close(peer);
    }
}

asocket* create_jdwp_service_socket(void) {
    JdwpSocket* s = new JdwpSocket();

    if (!s) {
        LOG(FATAL) << "failed to allocate JdwpSocket";
    }

    install_local_socket(s);

    s->ready = jdwp_socket_ready;
    s->enqueue = jdwp_socket_enqueue;
    s->close = jdwp_socket_close;
    s->pass = false;

    return s;
}

/** "track-jdwp" local service implementation
 ** this periodically sends the list of known JDWP process pids
 ** to the client...
 **/

struct JdwpTracker : public asocket {
    TrackerKind kind;
    bool need_initial;

    explicit JdwpTracker(TrackerKind k, bool initial) : kind(k), need_initial(initial) {}
};

static auto& _jdwp_trackers = *new std::vector<std::unique_ptr<JdwpTracker>>();

static void process_list_updated(TrackerKind kind) {
    std::string data;
    const int kMaxLength = kind == TrackerKind::kJdwp ? 1024 : 2048;
    data.resize(kMaxLength);
    data.resize(process_list_msg(kind, &data[0], data.size()));

    for (auto& t : _jdwp_trackers) {
        if (t->kind == kind && t->peer) {
            // The tracker might not have been connected yet.
            apacket::payload_type payload(data.begin(), data.end());
            t->peer->enqueue(t->peer, std::move(payload));
        }
    }
}

static void jdwp_process_list_updated(void) {
    process_list_updated(TrackerKind::kJdwp);
}

static void app_process_list_updated(void) {
    process_list_updated(TrackerKind::kApp);
}

static void jdwp_tracker_close(asocket* s) {
    D("LS(%d): destroying jdwp tracker service", s->id);

    if (s->peer) {
        D("LS(%d) peer->close()ing peer->id=%d peer->fd=%d", s->id, s->peer->id, s->peer->fd);
        s->peer->peer = nullptr;
        s->peer->close(s->peer);
        s->peer = nullptr;
    }

    remove_socket(s);

    auto pred = [s](const auto& tracker) { return tracker.get() == s; };
    _jdwp_trackers.erase(std::remove_if(_jdwp_trackers.begin(), _jdwp_trackers.end(), pred),
                         _jdwp_trackers.end());
}

static void jdwp_tracker_ready(asocket* s) {
    JdwpTracker* t = (JdwpTracker*)s;

    if (t->need_initial) {
        apacket::payload_type data;
        data.resize(s->get_max_payload());
        data.resize(process_list_msg(t->kind, &data[0], data.size()));
        t->need_initial = false;
        s->peer->enqueue(s->peer, std::move(data));
    }
}

static int jdwp_tracker_enqueue(asocket* s, apacket::payload_type) {
    /* you can't write to this socket */
    D("LS(%d): JDWP tracker received data?", s->id);
    s->peer->close(s->peer);
    return -1;
}

asocket* create_process_tracker_service_socket(TrackerKind kind) {
    auto t = std::make_unique<JdwpTracker>(kind, true);
    if (!t) {
        LOG(FATAL) << "failed to allocate JdwpTracker";
    }

    memset(t.get(), 0, sizeof(asocket));

    install_local_socket(t.get());
    D("LS(%d): created new jdwp tracker service", t->id);

    t->ready = jdwp_tracker_ready;
    t->enqueue = jdwp_tracker_enqueue;
    t->close = jdwp_tracker_close;

    asocket* result = t.get();

    _jdwp_trackers.emplace_back(std::move(t));

    return result;
}

asocket* create_jdwp_tracker_service_socket() {
    return create_process_tracker_service_socket(TrackerKind::kJdwp);
}

asocket* create_app_tracker_service_socket() {
    return create_process_tracker_service_socket(TrackerKind::kApp);
}

int init_jdwp(void) {
    std::thread([]() {
        adb_thread_setname("jdwp control");
        adbconnection_listen([](int fd, ProcessInfo process) {
            LOG(INFO) << "jdwp connection from " << process.pid;
            fdevent_run_on_main_thread([fd, process] {
                unique_fd ufd(fd);
                auto proc = std::make_unique<JdwpProcess>(std::move(ufd), process);
                if (!proc) {
                    LOG(FATAL) << "failed to allocate JdwpProcess";
                }
                _jdwp_list.emplace_back(std::move(proc));
                if (process.debuggable) jdwp_process_list_updated();
                if (process.debuggable || process.profileable) app_process_list_updated();
            });
        });
    }).detach();
    return 0;
}

#endif /* !ADB_HOST */
