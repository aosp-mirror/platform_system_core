/* system/debuggerd/debuggerd.c
**
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>
#include <time.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/exec_elf.h>
#include <sys/stat.h>
#include <sys/poll.h>

#include <log/logd.h>
#include <log/logger.h>

#include <cutils/sockets.h>
#include <cutils/properties.h>
#include <cutils/debugger.h>

#include <corkscrew/backtrace.h>

#include <linux/input.h>

#include <private/android_filesystem_config.h>

#include "backtrace.h"
#include "getevent.h"
#include "tombstone.h"
#include "utility.h"

typedef struct {
    debugger_action_t action;
    pid_t pid, tid;
    uid_t uid, gid;
    uintptr_t abort_msg_address;
} debugger_request_t;

static int
write_string(const char* file, const char* string)
{
    int len;
    int fd;
    ssize_t amt;
    fd = open(file, O_RDWR);
    len = strlen(string);
    if (fd < 0)
        return -errno;
    amt = write(fd, string, len);
    close(fd);
    return amt >= 0 ? 0 : -errno;
}

static
void init_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "0");
    write_string("/sys/class/leds/green/brightness", "0");
    write_string("/sys/class/leds/blue/brightness", "0");
    write_string("/sys/class/leds/red/device/blink", "0");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "0,0");
}

static
void enable_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "255");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "1,0");
}

static
void disable_debug_led(void)
{
    // trout leds
    write_string("/sys/class/leds/red/brightness", "0");
    // sardine leds
    write_string("/sys/class/leds/left/cadence", "0,0");
}

static void wait_for_user_action(pid_t pid) {
    /* First log a helpful message */
    LOG(    "********************************************************\n"
            "* Process %d has been suspended while crashing.  To\n"
            "* attach gdbserver for a gdb connection on port 5039\n"
            "* and start gdbclient:\n"
            "*\n"
            "*     gdbclient app_process :5039 %d\n"
            "*\n"
            "* Wait for gdb to start, then press HOME or VOLUME DOWN key\n"
            "* to let the process continue crashing.\n"
            "********************************************************\n",
            pid, pid);

    /* wait for HOME or VOLUME DOWN key */
    if (init_getevent() == 0) {
        int ms = 1200 / 10;
        int dit = 1;
        int dah = 3*dit;
        int _       = -dit;
        int ___     = 3*_;
        int _______ = 7*_;
        const signed char codes[] = {
           dit,_,dit,_,dit,___,dah,_,dah,_,dah,___,dit,_,dit,_,dit,_______
        };
        size_t s = 0;
        struct input_event e;
        bool done = false;
        init_debug_led();
        enable_debug_led();
        do {
            int timeout = abs((int)(codes[s])) * ms;
            int res = get_event(&e, timeout);
            if (res == 0) {
                if (e.type == EV_KEY
                        && (e.code == KEY_HOME || e.code == KEY_VOLUMEDOWN)
                        && e.value == 0) {
                    done = true;
                }
            } else if (res == 1) {
                if (++s >= sizeof(codes)/sizeof(*codes))
                    s = 0;
                if (codes[s] > 0) {
                    enable_debug_led();
                } else {
                    disable_debug_led();
                }
            }
        } while (!done);
        uninit_getevent();
    }

    /* don't forget to turn debug led off */
    disable_debug_led();
    LOG("debuggerd resuming process %d", pid);
}

static int get_process_info(pid_t tid, pid_t* out_pid, uid_t* out_uid, uid_t* out_gid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/status", tid);

    FILE* fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }

    int fields = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        if (len > 6 && !memcmp(line, "Tgid:\t", 6)) {
            *out_pid = atoi(line + 6);
            fields |= 1;
        } else if (len > 5 && !memcmp(line, "Uid:\t", 5)) {
            *out_uid = atoi(line + 5);
            fields |= 2;
        } else if (len > 5 && !memcmp(line, "Gid:\t", 5)) {
            *out_gid = atoi(line + 5);
            fields |= 4;
        }
    }
    fclose(fp);
    return fields == 7 ? 0 : -1;
}

static int read_request(int fd, debugger_request_t* out_request) {
    struct ucred cr;
    int len = sizeof(cr);
    int status = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
    if (status != 0) {
        LOG("cannot get credentials\n");
        return -1;
    }

    XLOG("reading tid\n");
    fcntl(fd, F_SETFL, O_NONBLOCK);

    struct pollfd pollfds[1];
    pollfds[0].fd = fd;
    pollfds[0].events = POLLIN;
    pollfds[0].revents = 0;
    status = TEMP_FAILURE_RETRY(poll(pollfds, 1, 3000));
    if (status != 1) {
        LOG("timed out reading tid (from pid=%d uid=%d)\n", cr.pid, cr.uid);
        return -1;
    }

    debugger_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    status = TEMP_FAILURE_RETRY(read(fd, &msg, sizeof(msg)));
    if (status < 0) {
        LOG("read failure? %s (pid=%d uid=%d)\n",
            strerror(errno), cr.pid, cr.uid);
        return -1;
    }
    if (status == sizeof(debugger_msg_t)) {
        XLOG("crash request of size %d abort_msg_address=%#08x\n", status, msg.abort_msg_address);
    } else {
        LOG("invalid crash request of size %d (from pid=%d uid=%d)\n",
            status, cr.pid, cr.uid);
        return -1;
    }

    out_request->action = msg.action;
    out_request->tid = msg.tid;
    out_request->pid = cr.pid;
    out_request->uid = cr.uid;
    out_request->gid = cr.gid;
    out_request->abort_msg_address = msg.abort_msg_address;

    if (msg.action == DEBUGGER_ACTION_CRASH) {
        /* Ensure that the tid reported by the crashing process is valid. */
        char buf[64];
        struct stat s;
        snprintf(buf, sizeof buf, "/proc/%d/task/%d", out_request->pid, out_request->tid);
        if(stat(buf, &s)) {
            LOG("tid %d does not exist in pid %d. ignoring debug request\n",
                    out_request->tid, out_request->pid);
            return -1;
        }
    } else if (cr.uid == 0
            || (cr.uid == AID_SYSTEM && msg.action == DEBUGGER_ACTION_DUMP_BACKTRACE)) {
        /* Only root or system can ask us to attach to any process and dump it explicitly.
         * However, system is only allowed to collect backtraces but cannot dump tombstones. */
        status = get_process_info(out_request->tid, &out_request->pid,
                &out_request->uid, &out_request->gid);
        if (status < 0) {
            LOG("tid %d does not exist. ignoring explicit dump request\n",
                    out_request->tid);
            return -1;
        }
    } else {
        /* No one else is allowed to dump arbitrary processes. */
        return -1;
    }
    return 0;
}

static bool should_attach_gdb(debugger_request_t* request) {
    if (request->action == DEBUGGER_ACTION_CRASH) {
        char value[PROPERTY_VALUE_MAX];
        property_get("debug.db.uid", value, "-1");
        int debug_uid = atoi(value);
        return debug_uid >= 0 && request->uid <= (uid_t)debug_uid;
    }
    return false;
}

static void handle_request(int fd) {
    XLOG("handle_request(%d)\n", fd);

    debugger_request_t request;
    memset(&request, 0, sizeof(request));
    int status = read_request(fd, &request);
    if (!status) {
        XLOG("BOOM: pid=%d uid=%d gid=%d tid=%d\n",
            request.pid, request.uid, request.gid, request.tid);

        /* At this point, the thread that made the request is blocked in
         * a read() call.  If the thread has crashed, then this gives us
         * time to PTRACE_ATTACH to it before it has a chance to really fault.
         *
         * The PTRACE_ATTACH sends a SIGSTOP to the target process, but it
         * won't necessarily have stopped by the time ptrace() returns.  (We
         * currently assume it does.)  We write to the file descriptor to
         * ensure that it can run as soon as we call PTRACE_CONT below.
         * See details in bionic/libc/linker/debugger.c, in function
         * debugger_signal_handler().
         */
        if (ptrace(PTRACE_ATTACH, request.tid, 0, 0)) {
            LOG("ptrace attach failed: %s\n", strerror(errno));
        } else {
            bool detach_failed = false;
            bool attach_gdb = should_attach_gdb(&request);
            if (TEMP_FAILURE_RETRY(write(fd, "\0", 1)) != 1) {
                LOG("failed responding to client: %s\n", strerror(errno));
            } else {
                char* tombstone_path = NULL;

                if (request.action == DEBUGGER_ACTION_CRASH) {
                    close(fd);
                    fd = -1;
                }

                int total_sleep_time_usec = 0;
                for (;;) {
                    int signal = wait_for_signal(request.tid, &total_sleep_time_usec);
                    if (signal < 0) {
                        break;
                    }

                    switch (signal) {
                    case SIGSTOP:
                        if (request.action == DEBUGGER_ACTION_DUMP_TOMBSTONE) {
                            XLOG("stopped -- dumping to tombstone\n");
                            tombstone_path = engrave_tombstone(request.pid, request.tid,
                                    signal, request.abort_msg_address, true, true, &detach_failed,
                                    &total_sleep_time_usec);
                        } else if (request.action == DEBUGGER_ACTION_DUMP_BACKTRACE) {
                            XLOG("stopped -- dumping to fd\n");
                            dump_backtrace(fd, -1,
                                    request.pid, request.tid, &detach_failed,
                                    &total_sleep_time_usec);
                        } else {
                            XLOG("stopped -- continuing\n");
                            status = ptrace(PTRACE_CONT, request.tid, 0, 0);
                            if (status) {
                                LOG("ptrace continue failed: %s\n", strerror(errno));
                            }
                            continue; /* loop again */
                        }
                        break;

                    case SIGILL:
                    case SIGABRT:
                    case SIGBUS:
                    case SIGFPE:
                    case SIGSEGV:
                    case SIGPIPE:
#ifdef SIGSTKFLT
                    case SIGSTKFLT:
#endif
                        {
                        XLOG("stopped -- fatal signal\n");
                        /*
                         * Send a SIGSTOP to the process to make all of
                         * the non-signaled threads stop moving.  Without
                         * this we get a lot of "ptrace detach failed:
                         * No such process".
                         */
                        kill(request.pid, SIGSTOP);
                        /* don't dump sibling threads when attaching to GDB because it
                         * makes the process less reliable, apparently... */
                        tombstone_path = engrave_tombstone(request.pid, request.tid,
                                signal, request.abort_msg_address, !attach_gdb, false,
                                &detach_failed, &total_sleep_time_usec);
                        break;
                    }

                    default:
                        XLOG("stopped -- unexpected signal\n");
                        LOG("process stopped due to unexpected signal %d\n", signal);
                        break;
                    }
                    break;
                }

                if (request.action == DEBUGGER_ACTION_DUMP_TOMBSTONE) {
                    if (tombstone_path) {
                        write(fd, tombstone_path, strlen(tombstone_path));
                    }
                    close(fd);
                    fd = -1;
                }
                free(tombstone_path);
            }

            XLOG("detaching\n");
            if (attach_gdb) {
                /* stop the process so we can debug */
                kill(request.pid, SIGSTOP);

                /* detach so we can attach gdbserver */
                if (ptrace(PTRACE_DETACH, request.tid, 0, 0)) {
                    LOG("ptrace detach from %d failed: %s\n", request.tid, strerror(errno));
                    detach_failed = true;
                }

                /*
                 * if debug.db.uid is set, its value indicates if we should wait
                 * for user action for the crashing process.
                 * in this case, we log a message and turn the debug LED on
                 * waiting for a gdb connection (for instance)
                 */
                wait_for_user_action(request.pid);
            } else {
                /* just detach */
                if (ptrace(PTRACE_DETACH, request.tid, 0, 0)) {
                    LOG("ptrace detach from %d failed: %s\n", request.tid, strerror(errno));
                    detach_failed = true;
                }
            }

            /* resume stopped process (so it can crash in peace). */
            kill(request.pid, SIGCONT);

            /* If we didn't successfully detach, we're still the parent, and the
             * actual parent won't receive a death notification via wait(2).  At this point
             * there's not much we can do about that. */
            if (detach_failed) {
                LOG("debuggerd committing suicide to free the zombie!\n");
                kill(getpid(), SIGKILL);
            }
        }

    }
    if (fd >= 0) {
        close(fd);
    }
}

static int do_server() {
    int s;
    struct sigaction act;
    int logsocket = -1;

    /*
     * debuggerd crashes can't be reported to debuggerd.  Reset all of the
     * crash handlers.
     */
    signal(SIGILL, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGFPE, SIG_DFL);
    signal(SIGSEGV, SIG_DFL);
#ifdef SIGSTKFLT
    signal(SIGSTKFLT, SIG_DFL);
#endif

    // Ignore failed writes to closed sockets
    signal(SIGPIPE, SIG_IGN);

    logsocket = socket_local_client("logd",
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_DGRAM);
    if(logsocket < 0) {
        logsocket = -1;
    } else {
        fcntl(logsocket, F_SETFD, FD_CLOEXEC);
    }

    act.sa_handler = SIG_DFL;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask,SIGCHLD);
    act.sa_flags = SA_NOCLDWAIT;
    sigaction(SIGCHLD, &act, 0);

    s = socket_local_server(DEBUGGER_SOCKET_NAME,
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    if(s < 0) return 1;
    fcntl(s, F_SETFD, FD_CLOEXEC);

    LOG("debuggerd: " __DATE__ " " __TIME__ "\n");

    for(;;) {
        struct sockaddr addr;
        socklen_t alen;
        int fd;

        alen = sizeof(addr);
        XLOG("waiting for connection\n");
        fd = accept(s, &addr, &alen);
        if(fd < 0) {
            XLOG("accept failed: %s\n", strerror(errno));
            continue;
        }

        fcntl(fd, F_SETFD, FD_CLOEXEC);

        handle_request(fd);
    }
    return 0;
}

static int do_explicit_dump(pid_t tid, bool dump_backtrace) {
    fprintf(stdout, "Sending request to dump task %d.\n", tid);

    if (dump_backtrace) {
        fflush(stdout);
        if (dump_backtrace_to_file(tid, fileno(stdout)) < 0) {
            fputs("Error dumping backtrace.\n", stderr);
            return 1;
        }
    } else {
        char tombstone_path[PATH_MAX];
        if (dump_tombstone(tid, tombstone_path, sizeof(tombstone_path)) < 0) {
            fputs("Error dumping tombstone.\n", stderr);
            return 1;
        }
        fprintf(stderr, "Tombstone written to: %s\n", tombstone_path);
    }
    return 0;
}

static void usage() {
    fputs("Usage: -b [<tid>]\n"
            "  -b dump backtrace to console, otherwise dump full tombstone file\n"
            "\n"
            "If tid specified, sends a request to debuggerd to dump that task.\n"
            "Otherwise, starts the debuggerd server.\n", stderr);
}

int main(int argc, char** argv) {
    if (argc == 1) {
        return do_server();
    }

    bool dump_backtrace = false;
    bool have_tid = false;
    pid_t tid = 0;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-b")) {
            dump_backtrace = true;
        } else if (!have_tid) {
            tid = atoi(argv[i]);
            have_tid = true;
        } else {
            usage();
            return 1;
        }
    }
    if (!have_tid) {
        usage();
        return 1;
    }
    return do_explicit_dump(tid, dump_backtrace);
}
