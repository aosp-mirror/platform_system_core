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

static void RunScript() {
    LOG(INFO) << "Attempting to run /first_stage.sh...";
    pid_t pid = fork();
    if (pid != 0) {
        int status;
        waitpid(pid, &status, 0);
        LOG(INFO) << "/first_stage.sh exited with status " << status;
        return;
    }
    const char* path = "/system/bin/sh";
    const char* args[] = {path, "/first_stage.sh", nullptr};
    int rv = execv(path, const_cast<char**>(args));
    LOG(ERROR) << "unable to execv /first_stage.sh, returned " << rv << " errno " << errno;
}

namespace android {
namespace init {

void StartConsole() {
    if (mknod("/dev/console", S_IFCHR | 0600, makedev(5, 1))) {
        PLOG(ERROR) << "unable to create /dev/console";
        return;
    }
    pid_t pid = fork();
    if (pid != 0) {
        int status;
        waitpid(pid, &status, 0);
        LOG(ERROR) << "console shell exited with status " << status;
        return;
    }
    int fd = -1;
    int tries = 50; // should timeout after 5s
    // The device driver for console may not be ready yet so retry for a while in case of failure.
    while (tries--) {
        fd = open("/dev/console", O_RDWR);
        if (fd != -1) {
            break;
        }
        std::this_thread::sleep_for(100ms);
    }
    if (fd == -1) {
        LOG(ERROR) << "Could not open /dev/console, errno = " << errno;
        _exit(127);
    }
    ioctl(fd, TIOCSCTTY, 0);
    dup2(fd, STDIN_FILENO);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);

    RunScript();
    const char* path = "/system/bin/sh";
    const char* args[] = {path, nullptr};
    int rv = execv(path, const_cast<char**>(args));
    LOG(ERROR) << "unable to execv, returned " << rv << " errno " << errno;
    _exit(127);
}

int FirstStageConsole(const std::string& cmdline) {
    auto pos = cmdline.find("androidboot.first_stage_console=");
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
