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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <list>
#include <memory>
#include <vector>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"

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

// PIDs are transmitted as 4 hex digits in ascii.
static constexpr size_t PID_LEN = 4;

static void jdwp_process_event(int socket, unsigned events, void* _proc);
static void jdwp_process_list_updated(void);

struct JdwpProcess;
static std::list<std::unique_ptr<JdwpProcess>> _jdwp_list;

struct JdwpProcess {
    explicit JdwpProcess(int socket) {
        this->socket = socket;
        this->fde = fdevent_create(socket, jdwp_process_event, this);

        if (!this->fde) {
            fatal("could not create fdevent for new JDWP process");
        }

        this->fde->state |= FDE_DONT_CLOSE;

        /* start by waiting for the PID */
        fdevent_add(this->fde, FDE_READ);
    }

    ~JdwpProcess() {
        if (this->socket >= 0) {
            adb_shutdown(this->socket);
            adb_close(this->socket);
            this->socket = -1;
        }

        if (this->fde) {
            fdevent_destroy(this->fde);
            this->fde = nullptr;
        }

        out_fds.clear();
    }

    void RemoveFromList() {
        if (this->pid >= 0) {
            D("removing pid %d from jdwp process list", this->pid);
        } else {
            D("removing transient JdwpProcess from list");
        }

        auto pred = [this](const auto& proc) { return proc.get() == this; };
        _jdwp_list.remove_if(pred);
    }

    int pid = -1;
    int socket = -1;
    fdevent* fde = nullptr;

    std::vector<unique_fd> out_fds;
};

static size_t jdwp_process_list(char* buffer, size_t bufferlen) {
    std::string temp;

    for (auto& proc : _jdwp_list) {
        /* skip transient connections */
        if (proc->pid < 0) {
            continue;
        }

        std::string next = std::to_string(proc->pid) + "\n";
        if (temp.length() + next.length() > bufferlen) {
            D("truncating JDWP process list (max len = %zu)", bufferlen);
            break;
        }
        temp.append(next);
    }

    memcpy(buffer, temp.data(), temp.length());
    return temp.length();
}

static size_t jdwp_process_list_msg(char* buffer, size_t bufferlen) {
    // Message is length-prefixed with 4 hex digits in ASCII.
    static constexpr size_t header_len = 4;
    if (bufferlen < header_len) {
        fatal("invalid JDWP process list buffer size: %zu", bufferlen);
    }

    char head[header_len + 1];
    size_t len = jdwp_process_list(buffer + header_len, bufferlen - header_len);
    snprintf(head, sizeof head, "%04zx", len);
    memcpy(buffer, head, header_len);
    return len + header_len;
}

static void jdwp_process_event(int socket, unsigned events, void* _proc) {
    JdwpProcess* proc = reinterpret_cast<JdwpProcess*>(_proc);

    if (events & FDE_READ) {
        if (proc->pid < 0) {
            /* read the PID as a 4-hexchar string */
            char buf[PID_LEN + 1];
            ssize_t rc = TEMP_FAILURE_RETRY(recv(socket, buf, PID_LEN, 0));
            if (rc != PID_LEN) {
                D("failed to read jdwp pid: %s", strerror(errno));
                goto CloseProcess;
            }
            buf[PID_LEN] = '\0';

            if (sscanf(buf, "%04x", &proc->pid) != 1) {
                D("could not decode JDWP %p PID number: '%s'", proc, buf);
                goto CloseProcess;
            }

            /* all is well, keep reading to detect connection closure */
            D("Adding pid %d to jdwp process list", proc->pid);
            jdwp_process_list_updated();
        } else {
            /* the pid was read, if we get there it's probably because the connection
             * was closed (e.g. the JDWP process exited or crashed) */
            char buf[32];

            while (true) {
                int len = TEMP_FAILURE_RETRY(recv(socket, buf, sizeof(buf), 0));

                if (len == 0) {
                    D("terminating JDWP %d connection: EOF", proc->pid);
                    break;
                } else if (len < 0) {
                    if (len < 0 && errno == EAGAIN) {
                        return;
                    }

                    D("terminating JDWP %d connection: EOF", proc->pid);
                    break;
                } else {
                    D("ignoring unexpected JDWP %d control socket activity (%d bytes)", proc->pid,
                      len);
                }
            }

            goto CloseProcess;
        }
    }

    if (events & FDE_WRITE) {
        D("trying to send fd to JDWP process (count = %zu)", proc->out_fds.size());
        if (!proc->out_fds.empty()) {
            int fd = proc->out_fds.back().get();
            struct cmsghdr* cmsg;
            struct msghdr msg;
            struct iovec iov;
            char dummy = '!';
            char buffer[sizeof(struct cmsghdr) + sizeof(int)];

            iov.iov_base = &dummy;
            iov.iov_len = 1;
            msg.msg_name = NULL;
            msg.msg_namelen = 0;
            msg.msg_iov = &iov;
            msg.msg_iovlen = 1;
            msg.msg_flags = 0;
            msg.msg_control = buffer;
            msg.msg_controllen = sizeof(buffer);

            cmsg = CMSG_FIRSTHDR(&msg);
            cmsg->cmsg_len = msg.msg_controllen;
            cmsg->cmsg_level = SOL_SOCKET;
            cmsg->cmsg_type = SCM_RIGHTS;
            ((int*)CMSG_DATA(cmsg))[0] = fd;

            if (!set_file_block_mode(proc->socket, true)) {
                VLOG(JDWP) << "failed to set blocking mode for fd " << proc->socket;
                goto CloseProcess;
            }

            int ret = TEMP_FAILURE_RETRY(sendmsg(proc->socket, &msg, 0));
            if (ret < 0) {
                D("sending new file descriptor to JDWP %d failed: %s", proc->pid, strerror(errno));
                goto CloseProcess;
            }

            adb_close(fd);

            D("sent file descriptor %d to JDWP process %d", fd, proc->pid);

            proc->out_fds.pop_back();

            if (!set_file_block_mode(proc->socket, false)) {
                VLOG(JDWP) << "failed to set non-blocking mode for fd " << proc->socket;
                goto CloseProcess;
            }

            if (proc->out_fds.empty()) {
                fdevent_del(proc->fde, FDE_WRITE);
            }
        }
    }

    return;

CloseProcess:
    proc->RemoveFromList();
    jdwp_process_list_updated();
}

int create_jdwp_connection_fd(int pid) {
    D("looking for pid %d in JDWP process list", pid);

    for (auto& proc : _jdwp_list) {
        if (proc->pid == pid) {
            int fds[2];

            if (adb_socketpair(fds) < 0) {
                D("%s: socket pair creation failed: %s", __FUNCTION__, strerror(errno));
                return -1;
            }
            D("socketpair: (%d,%d)", fds[0], fds[1]);

            proc->out_fds.emplace_back(fds[1]);
            if (proc->out_fds.size() == 1) {
                fdevent_add(proc->fde, FDE_WRITE);
            }

            return fds[0];
        }
    }
    D("search failed !!");
    return -1;
}

/**  VM DEBUG CONTROL SOCKET
 **
 **  we do implement a custom asocket to receive the data
 **/

/* name of the debug control Unix socket */
#define JDWP_CONTROL_NAME "\0jdwp-control"
#define JDWP_CONTROL_NAME_LEN (sizeof(JDWP_CONTROL_NAME) - 1)

struct JdwpControl {
    int listen_socket;
    fdevent* fde;
};

static JdwpControl _jdwp_control;

static void jdwp_control_event(int s, unsigned events, void* user);

static int jdwp_control_init(JdwpControl* control, const char* sockname, int socknamelen) {
    sockaddr_un addr;
    socklen_t addrlen;
    int s;
    int maxpath = sizeof(addr.sun_path);
    int pathlen = socknamelen;

    if (pathlen >= maxpath) {
        D("vm debug control socket name too long (%d extra chars)", pathlen + 1 - maxpath);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    memcpy(addr.sun_path, sockname, socknamelen);

    s = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
    if (s < 0) {
        D("could not create vm debug control socket. %d: %s", errno, strerror(errno));
        return -1;
    }

    addrlen = pathlen + sizeof(addr.sun_family);

    if (bind(s, reinterpret_cast<sockaddr*>(&addr), addrlen) < 0) {
        D("could not bind vm debug control socket: %d: %s", errno, strerror(errno));
        adb_close(s);
        return -1;
    }

    if (listen(s, 4) < 0) {
        D("listen failed in jdwp control socket: %d: %s", errno, strerror(errno));
        adb_close(s);
        return -1;
    }

    control->listen_socket = s;

    control->fde = fdevent_create(s, jdwp_control_event, control);
    if (control->fde == NULL) {
        D("could not create fdevent for jdwp control socket");
        adb_close(s);
        return -1;
    }

    /* only wait for incoming connections */
    fdevent_add(control->fde, FDE_READ);

    D("jdwp control socket started (%d)", control->listen_socket);
    return 0;
}

static void jdwp_control_event(int s, unsigned events, void* _control) {
    JdwpControl* control = (JdwpControl*)_control;

    if (events & FDE_READ) {
        int s = adb_socket_accept(control->listen_socket, nullptr, nullptr);
        if (s < 0) {
            if (errno == ECONNABORTED) {
                /* oops, the JDWP process died really quick */
                D("oops, the JDWP process died really quick");
                return;
            } else {
                /* the socket is probably closed ? */
                D("weird accept() failed on jdwp control socket: %s", strerror(errno));
                return;
            }
        }

        auto proc = std::make_unique<JdwpProcess>(s);
        if (!proc) {
            fatal("failed to allocate JdwpProcess");
        }

        _jdwp_list.emplace_back(std::move(proc));
    }
}

/** "jdwp" local service implementation
 ** this simply returns the list of known JDWP process pids
 **/

struct JdwpSocket : public asocket {
    bool pass;
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
    free(s);
}

static int jdwp_socket_enqueue(asocket* s, std::string) {
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
        std::string data;
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
    JdwpSocket* s = reinterpret_cast<JdwpSocket*>(calloc(sizeof(*s), 1));

    if (!s) {
        fatal("failed to allocate JdwpSocket");
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
    bool need_initial;
};

static std::vector<std::unique_ptr<JdwpTracker>> _jdwp_trackers;

static void jdwp_process_list_updated(void) {
    std::string data;
    data.resize(1024);
    data.resize(jdwp_process_list_msg(&data[0], data.size()));

    for (auto& t : _jdwp_trackers) {
        if (t->peer) {
            // The tracker might not have been connected yet.
            t->peer->enqueue(t->peer, data);
        }
    }
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
        std::string data;
        data.resize(s->get_max_payload());
        data.resize(jdwp_process_list_msg(&data[0], data.size()));
        t->need_initial = false;
        s->peer->enqueue(s->peer, std::move(data));
    }
}

static int jdwp_tracker_enqueue(asocket* s, std::string) {
    /* you can't write to this socket */
    D("LS(%d): JDWP tracker received data?", s->id);
    s->peer->close(s->peer);
    return -1;
}

asocket* create_jdwp_tracker_service_socket(void) {
    auto t = std::make_unique<JdwpTracker>();
    if (!t) {
        fatal("failed to allocate JdwpTracker");
    }

    memset(t.get(), 0, sizeof(asocket));

    install_local_socket(t.get());
    D("LS(%d): created new jdwp tracker service", t->id);

    t->ready = jdwp_tracker_ready;
    t->enqueue = jdwp_tracker_enqueue;
    t->close = jdwp_tracker_close;
    t->need_initial = true;

    asocket* result = t.get();

    _jdwp_trackers.emplace_back(std::move(t));

    return result;
}

int init_jdwp(void) {
    return jdwp_control_init(&_jdwp_control, JDWP_CONTROL_NAME, JDWP_CONTROL_NAME_LEN);
}

#endif /* !ADB_HOST */
