/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <base/stringprintf.h>
#include <cutils/android_reboot.h>
#include <cutils/list.h>
#include <cutils/sockets.h>

#include "init.h"
#include "log.h"
#include "util.h"

#define CRITICAL_CRASH_THRESHOLD    4       /* if we crash >4 times ... */
#define CRITICAL_CRASH_WINDOW       (4*60)  /* ... in 4 minutes, goto recovery */

static int signal_write_fd = -1;
static int signal_read_fd = -1;

static std::string DescribeStatus(int status) {
    if (WIFEXITED(status)) {
        return android::base::StringPrintf("exited with status %d", WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        return android::base::StringPrintf("killed by signal %d", WTERMSIG(status));
    } else if (WIFSTOPPED(status)) {
        return android::base::StringPrintf("stopped by signal %d", WSTOPSIG(status));
    } else {
        return "state changed";
    }
}

static bool wait_for_one_process() {
    int status;
    pid_t pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, WNOHANG));
    if (pid == 0) {
        return false;
    } else if (pid == -1) {
        ERROR("waitpid failed: %s\n", strerror(errno));
        return false;
    }

    service* svc = service_find_by_pid(pid);

    std::string name;
    if (svc) {
        name = android::base::StringPrintf("Service '%s' (pid %d)", svc->name, pid);
    } else {
        name = android::base::StringPrintf("Untracked pid %d", pid);
    }

    NOTICE("%s %s\n", name.c_str(), DescribeStatus(status).c_str());

    if (!svc) {
        return true;
    }

    // TODO: all the code from here down should be a member function on service.

    if (!(svc->flags & SVC_ONESHOT) || (svc->flags & SVC_RESTART)) {
        NOTICE("Service '%s' (pid %d) killing any children in process group\n", svc->name, pid);
        kill(-pid, SIGKILL);
    }

    // Remove any sockets we may have created.
    for (socketinfo* si = svc->sockets; si; si = si->next) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), ANDROID_SOCKET_DIR"/%s", si->name);
        unlink(tmp);
    }

    if (svc->flags & SVC_EXEC) {
        INFO("SVC_EXEC pid %d finished...\n", svc->pid);
        waiting_for_exec = false;
        list_remove(&svc->slist);
        free(svc->name);
        free(svc);
        return true;
    }

    svc->pid = 0;
    svc->flags &= (~SVC_RUNNING);

    // Oneshot processes go into the disabled state on exit,
    // except when manually restarted.
    if ((svc->flags & SVC_ONESHOT) && !(svc->flags & SVC_RESTART)) {
        svc->flags |= SVC_DISABLED;
    }

    // Disabled and reset processes do not get restarted automatically.
    if (svc->flags & (SVC_DISABLED | SVC_RESET))  {
        svc->NotifyStateChange("stopped");
        return true;
    }

    time_t now = gettime();
    if ((svc->flags & SVC_CRITICAL) && !(svc->flags & SVC_RESTART)) {
        if (svc->time_crashed + CRITICAL_CRASH_WINDOW >= now) {
            if (++svc->nr_crashed > CRITICAL_CRASH_THRESHOLD) {
                ERROR("critical process '%s' exited %d times in %d minutes; "
                      "rebooting into recovery mode\n", svc->name,
                      CRITICAL_CRASH_THRESHOLD, CRITICAL_CRASH_WINDOW / 60);
                android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
                return true;
            }
        } else {
            svc->time_crashed = now;
            svc->nr_crashed = 1;
        }
    }

    svc->flags &= (~SVC_RESTART);
    svc->flags |= SVC_RESTARTING;

    // Execute all onrestart commands for this service.
    struct listnode* node;
    list_for_each(node, &svc->onrestart.commands) {
        command* cmd = node_to_item(node, struct command, clist);
        cmd->func(cmd->nargs, cmd->args);
    }
    svc->NotifyStateChange("restarting");
    return true;
}

static void reap_any_outstanding_children() {
    while (wait_for_one_process()) {
    }
}

static void handle_signal() {
    // Clear outstanding requests.
    char buf[32];
    read(signal_read_fd, buf, sizeof(buf));

    reap_any_outstanding_children();
}

static void SIGCHLD_handler(int) {
    if (TEMP_FAILURE_RETRY(write(signal_write_fd, "1", 1)) == -1) {
        ERROR("write(signal_write_fd) failed: %s\n", strerror(errno));
    }
}

void signal_handler_init() {
    // Create a signalling mechanism for SIGCHLD.
    int s[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, s) == -1) {
        ERROR("socketpair failed: %s\n", strerror(errno));
        exit(1);
    }

    signal_write_fd = s[0];
    signal_read_fd = s[1];

    // Write to signal_write_fd if we catch SIGCHLD.
    struct sigaction act;
    memset(&act, 0, sizeof(act));
    act.sa_handler = SIGCHLD_handler;
    act.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &act, 0);

    reap_any_outstanding_children();

    register_epoll_handler(signal_read_fd, handle_signal);
}
