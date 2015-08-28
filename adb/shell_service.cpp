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

#define TRACE_TAG TRACE_SHELL

#include "shell_service.h"

#if !ADB_HOST

#include <pty.h>
#include <termios.h>

#include <paths.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_trace.h"
#include "sysdeps.h"

namespace {

void init_subproc_child()
{
    setsid();

    // Set OOM score adjustment to prevent killing
    int fd = adb_open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        adb_write(fd, "0", 1);
        adb_close(fd);
    } else {
       D("adb: unable to update oom_score_adj");
    }
}

int create_subproc_pty(const char* cmd, const char* arg0, const char* arg1,
                       pid_t* pid) {
    D("create_subproc_pty(cmd=%s, arg0=%s, arg1=%s)", cmd, arg0, arg1);
    char pts_name[PATH_MAX];
    int ptm;
    *pid = forkpty(&ptm, pts_name, nullptr, nullptr);
    if (*pid == -1) {
        printf("- fork failed: %s -\n", strerror(errno));
        unix_close(ptm);
        return -1;
    }

    if (*pid == 0) {
        init_subproc_child();

        int pts = unix_open(pts_name, O_RDWR | O_CLOEXEC);
        if (pts == -1) {
            fprintf(stderr, "child failed to open pseudo-term slave %s: %s\n",
                    pts_name, strerror(errno));
            unix_close(ptm);
            exit(-1);
        }

        // arg0 is "-c" in batch mode and "-" in interactive mode.
        if (strcmp(arg0, "-c") == 0) {
            termios tattr;
            if (tcgetattr(pts, &tattr) == -1) {
                fprintf(stderr, "tcgetattr failed: %s\n", strerror(errno));
                unix_close(pts);
                unix_close(ptm);
                exit(-1);
            }

            cfmakeraw(&tattr);
            if (tcsetattr(pts, TCSADRAIN, &tattr) == -1) {
                fprintf(stderr, "tcsetattr failed: %s\n", strerror(errno));
                unix_close(pts);
                unix_close(ptm);
                exit(-1);
            }
        }

        dup2(pts, STDIN_FILENO);
        dup2(pts, STDOUT_FILENO);
        dup2(pts, STDERR_FILENO);

        unix_close(pts);
        unix_close(ptm);

        execl(cmd, cmd, arg0, arg1, nullptr);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        return ptm;
    }
}

int create_subproc_raw(const char *cmd, const char *arg0, const char *arg1,
                       pid_t *pid)
{
    D("create_subproc_raw(cmd=%s, arg0=%s, arg1=%s)", cmd, arg0, arg1);

    // 0 is parent socket, 1 is child socket
    int sv[2];
    if (adb_socketpair(sv) < 0) {
        printf("[ cannot create socket pair - %s ]\n", strerror(errno));
        return -1;
    }
    D("socketpair: (%d,%d)", sv[0], sv[1]);

    *pid = fork();
    if (*pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        adb_close(sv[0]);
        adb_close(sv[1]);
        return -1;
    }

    if (*pid == 0) {
        adb_close(sv[0]);
        init_subproc_child();

        dup2(sv[1], STDIN_FILENO);
        dup2(sv[1], STDOUT_FILENO);
        dup2(sv[1], STDERR_FILENO);

        adb_close(sv[1]);

        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        adb_close(sv[1]);
        return sv[0];
    }
}

void subproc_waiter_service(int fd, void *cookie)
{
    pid_t pid = (pid_t) (uintptr_t) cookie;

    D("entered. fd=%d of pid=%d", fd, pid);
    while (true) {
        int status;
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            D("fd=%d, post waitpid(pid=%d) status=%04x", fd, p, status);
            if (WIFSIGNALED(status)) {
                D("*** Killed by signal %d", WTERMSIG(status));
                break;
            } else if (!WIFEXITED(status)) {
                D("*** Didn't exit!!. status %d", status);
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                D("*** Exit code %d", WEXITSTATUS(status));
                break;
            }
         }
    }
    D("shell exited fd=%d of pid=%d err=%d", fd, pid, errno);
    if (SHELL_EXIT_NOTIFY_FD >=0) {
      int res;
      res = WriteFdExactly(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd)) ? 0 : -1;
      D("notified shell exit via fd=%d for pid=%d res=%d errno=%d",
        SHELL_EXIT_NOTIFY_FD, pid, res, errno);
    }
}

}  // namespace

// References to things in services.cpp. This is temporary just to make as few
// modifications as possible while moving functionality into it's own file.
// TODO(dpursell): remove these in the next CL.
void *service_bootstrap_func(void *x);
struct stinfo_duplicate {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};

int StartSubprocess(const char *name, SubprocessType type) {
    const char *arg0, *arg1;
    if (*name == '\0') {
        arg0 = "-";
        arg1 = nullptr;
    } else {
        arg0 = "-c";
        arg1 = name;
    }

    pid_t pid = -1;
    int ret_fd;
    if (type == SubprocessType::kPty) {
        ret_fd = create_subproc_pty(_PATH_BSHELL, arg0, arg1, &pid);
    } else {
        ret_fd = create_subproc_raw(_PATH_BSHELL, arg0, arg1, &pid);
    }
    D("create_subproc ret_fd=%d pid=%d", ret_fd, pid);

    stinfo_duplicate* sti = reinterpret_cast<stinfo_duplicate*>(malloc(sizeof(stinfo_duplicate)));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*) (uintptr_t) pid;
    sti->fd = ret_fd;

    if (!adb_thread_create(service_bootstrap_func, sti)) {
        free(sti);
        adb_close(ret_fd);
        fprintf(stderr, "cannot create service thread\n");
        return -1;
    }

    D("service thread started, fd=%d pid=%d", ret_fd, pid);
    return ret_fd;
}

#endif  // !ADB_HOST
