/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <string>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"

void remount_service(unique_fd fd, const std::string& cmd) {
    static constexpr char remount_cmd[] = "/system/bin/remount";
    static constexpr char remount_failed[] = "remount failed\n";

    if (getuid() != 0) {
        WriteFdExactly(fd.get(), "Not running as root. Try \"adb root\" first.\n");
        WriteFdExactly(fd.get(), remount_failed);
        return;
    }

    auto pid = vfork();
    if (pid < 0) {
        WriteFdFmt(fd.get(), "Failed to fork to %s: %s\n", remount_cmd, strerror(errno));
        WriteFdExactly(fd.get(), remount_failed);
        return;
    }

    if (pid == 0) {
        // child side of the fork
        fcntl(fd.get(), F_SETFD, 0);
        dup2(fd.get(), STDIN_FILENO);
        dup2(fd.get(), STDOUT_FILENO);
        dup2(fd.get(), STDERR_FILENO);

        execl(remount_cmd, remount_cmd, cmd.empty() ? nullptr : cmd.c_str(), nullptr);
        _exit(-errno ?: 42);
    }

    int wstatus = 0;
    auto ret = waitpid(pid, &wstatus, 0);

    if (ret == -1) {
        WriteFdFmt(fd.get(), "Failed to wait for %s: %s\n", remount_cmd, strerror(errno));
        goto err;
    }

    if (ret != pid) {
        WriteFdFmt(fd.get(), "pid %d and waitpid return %d do not match for %s\n",
                   static_cast<int>(pid), static_cast<int>(ret), remount_cmd);
        goto err;
    }

    if (WIFSIGNALED(wstatus)) {
        WriteFdFmt(fd.get(), "%s terminated with signal %s\n", remount_cmd,
                   strsignal(WTERMSIG(wstatus)));
        goto err;
    }

    if (!WIFEXITED(wstatus)) {
        WriteFdFmt(fd.get(), "%s stopped with status 0x%x\n", remount_cmd, wstatus);
        goto err;
    }

    if (WEXITSTATUS(wstatus)) {
        WriteFdFmt(fd.get(), "%s exited with status %d\n", remount_cmd,
                   static_cast<signed char>(WEXITSTATUS(wstatus)));
        goto err;
    }

    WriteFdExactly(fd.get(), "remount succeeded\n");
    return;

err:
    WriteFdExactly(fd.get(), remount_failed);
}
