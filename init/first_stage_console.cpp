/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "first_stage_console.h"

#include <spawn.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>

#include <string>
#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>

static bool KernelConsolePresent(const std::string& cmdline) {
    size_t pos = 0;
    while (true) {
        pos = cmdline.find("console=", pos);
        if (pos == std::string::npos) return false;
        if (pos == 0 || cmdline[pos - 1] == ' ') return true;
        pos++;
    }
}

static bool SetupConsole() {
    if (mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1))) {
        PLOG(ERROR) << "unable to create /dev/console";
        return false;
    }
    int fd = -1;
    int tries = 50;  // should timeout after 5s
    // The device driver for console may not be ready yet so retry for a while in case of failure.
    while (tries--) {
        fd = open("/dev/console", O_RDWR);
        if (fd != -1) break;
        std::this_thread::sleep_for(100ms);
    }
    if (fd == -1) {
        PLOG(ERROR) << "could not open /dev/console";
        return false;
    }
    ioctl(fd, TIOCSCTTY, 0);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    return true;
}

static pid_t SpawnImage(const char* file) {
    const char* argv[] = {file, NULL};
    const char* envp[] = {NULL};

    char* const* argvp = const_cast<char* const*>(argv);
    char* const* envpp = const_cast<char* const*>(envp);

    pid_t pid;
    errno = posix_spawn(&pid, argv[0], NULL, NULL, argvp, envpp);
    if (!errno) return pid;

    PLOG(ERROR) << "Failed to spawn '" << file << "'";

    return (pid_t)0;
}

namespace android {
namespace init {

void StartConsole(const std::string& cmdline) {
    bool console = KernelConsolePresent(cmdline);
    // Use a simple sigchld handler -- first_stage_console doesn't need to track or log zombies
    const struct sigaction chld_act {
        .sa_flags = SA_NOCLDWAIT, .sa_handler = SIG_DFL
    };

    sigaction(SIGCHLD, &chld_act, nullptr);
    pid_t pid = fork();
    if (pid != 0) {
        wait(NULL);
        LOG(ERROR) << "console shell exited";
        return;
    }

    if (console) console = SetupConsole();

    LOG(INFO) << "Attempting to run /first_stage.sh...";
    if (SpawnImage("/first_stage.sh")) {
        wait(NULL);
        LOG(INFO) << "/first_stage.sh exited";
    }

    if (console) {
        if (SpawnImage("/system/bin/sh")) wait(NULL);
    }
    _exit(127);
}

int FirstStageConsole(const std::string& cmdline, const std::string& bootconfig) {
    auto pos = bootconfig.find("androidboot.first_stage_console =");
    if (pos != std::string::npos) {
        int val = 0;
        if (sscanf(bootconfig.c_str() + pos, "androidboot.first_stage_console = \"%d\"", &val) !=
            1) {
            return FirstStageConsoleParam::DISABLED;
        }
        if (val <= FirstStageConsoleParam::MAX_PARAM_VALUE && val >= 0) {
            return val;
        }
    }

    pos = cmdline.find("androidboot.first_stage_console=");
    if (pos != std::string::npos) {
        int val = 0;
        if (sscanf(cmdline.c_str() + pos, "androidboot.first_stage_console=%d", &val) != 1) {
            return FirstStageConsoleParam::DISABLED;
        }
        if (val <= FirstStageConsoleParam::MAX_PARAM_VALUE && val >= 0) {
            return val;
        }
    }
    return FirstStageConsoleParam::DISABLED;
}

}  // namespace init
}  // namespace android
