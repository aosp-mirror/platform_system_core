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

#include <android-base/stringprintf.h>
#include <cutils/android_reboot.h>
#include <cutils/list.h>
#include <cutils/sockets.h>

#include "action.h"
#include "init.h"
#include "log.h"
#include "service.h"
#include "util.h"

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

    Service* svc = ServiceManager::GetInstance().FindServiceByPid(pid);

    std::string name;
    if (svc) {
        name = android::base::StringPrintf("Service '%s' (pid %d)", svc->name().c_str(), pid);
    } else {
        name = android::base::StringPrintf("Untracked pid %d", pid);
    }

    NOTICE("%s %s\n", name.c_str(), DescribeStatus(status).c_str());

    if (!svc) {
        return true;
    }

    if (svc->Reap()) {
        waiting_for_exec = false;
        ServiceManager::GetInstance().RemoveService(*svc);
    }

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
