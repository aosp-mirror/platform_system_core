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

static constexpr char kRemountCmd[] = "/system/bin/remount";

static bool do_remount(int fd, const std::string& cmd) {
    if (getuid() != 0) {
        WriteFdExactly(fd, "Not running as root. Try \"adb root\" first.\n");
        return false;
    }

    auto pid = fork();
    if (pid < 0) {
        WriteFdFmt(fd, "Failed to fork to %s: %s\n", kRemountCmd, strerror(errno));
        return false;
    }

    if (pid == 0) {
        // child side of the fork
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);

        execl(kRemountCmd, kRemountCmd, cmd.empty() ? nullptr : cmd.c_str(), nullptr);
        _exit(errno);
    }

    int wstatus = 0;
    auto ret = waitpid(pid, &wstatus, 0);

    if (ret == -1) {
        WriteFdFmt(fd, "Failed to wait for %s: %s\n", kRemountCmd, strerror(errno));
        return false;
    } else if (ret != pid) {
        WriteFdFmt(fd, "pid %d and waitpid return %d do not match for %s\n",
                   static_cast<int>(pid), static_cast<int>(ret), kRemountCmd);
        return false;
    }

    if (WIFSIGNALED(wstatus)) {
        WriteFdFmt(fd, "%s terminated with signal %s\n", kRemountCmd,
                   strsignal(WTERMSIG(wstatus)));
        return false;
    }

    if (!WIFEXITED(wstatus)) {
        WriteFdFmt(fd, "%s stopped with status 0x%x\n", kRemountCmd, wstatus);
        return false;
    }

    if (WEXITSTATUS(wstatus)) {
        WriteFdFmt(fd, "%s exited with status %d\n", kRemountCmd, WEXITSTATUS(wstatus));
        return false;
    }

    return true;
}

void remount_service(unique_fd fd, const std::string& cmd) {
    const char* success = do_remount(fd.get(), cmd) ? "succeeded" : "failed";
    WriteFdFmt(fd.get(), "remount %s\n", success);
}
