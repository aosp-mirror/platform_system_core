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
#include <string.h>

#define LOG_TAG "FrameworkListener"

#include <cutils/log.h>

#include <sysutils/FrameworkListener.h>
#include <sysutils/FrameworkCommand.h>

FrameworkListener::FrameworkListener(const char *socketName) :
                            SocketListener(socketName, true) {
    mCommands = new FrameworkCommandCollection();
}

bool FrameworkListener::onDataAvailable(int socket) {
    char buffer[101];
    int len;

    if ((len = read(socket, buffer, sizeof(buffer) -1)) < 0) {
        LOGE("read() failed (%s)", strerror(errno));
        return errno;
    } else if (!len) {
        LOGW("Lost connection to client");
        return false;
    }

    int start = 0;
    int i;

    buffer[len] = '\0';

    for (i = 0; i < len; i++) {
        if (buffer[i] == '\0') {
            dispatchCommand(buffer + start);
            start = i + 1;
        }
    }
    return true;
}

void FrameworkListener::registerCmd(FrameworkCommand *cmd) {
    mCommands->push_back(cmd);
}

void FrameworkListener::dispatchCommand(char *cmd) {
    FrameworkCommandCollection::iterator i;

    for (i = mCommands->begin(); i != mCommands->end(); ++i) {
        FrameworkCommand *c = *i;

        if (!strncmp(cmd, c->getCommand(), strlen(c->getCommand()))) {
            if (c->runCommand(cmd)) {
                LOGW("Handler '%s' error (%s)", c->getCommand(), strerror(errno));
            }
            return;
        }
    }

    LOGE("No cmd handlers defined for '%s'", cmd);
}

