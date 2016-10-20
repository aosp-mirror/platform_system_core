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

#define LOG_TAG "FrameworkCommand"

#include <errno.h>

#include <log/log.h>
#include <sysutils/FrameworkCommand.h>

#define UNUSED __attribute__((unused))

FrameworkCommand::FrameworkCommand(const char *cmd) {
    mCommand = cmd;
}

int FrameworkCommand::runCommand(SocketClient *c UNUSED, int argc UNUSED,
                                 char **argv UNUSED) {
    SLOGW("Command %s has no run handler!", getCommand());
    errno = ENOSYS;
    return -1;
}
