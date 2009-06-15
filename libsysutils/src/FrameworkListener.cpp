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
#include <sysutils/SocketClient.h>

FrameworkListener::FrameworkListener(const char *socketName) :
                            SocketListener(socketName, true) {
    mCommands = new FrameworkCommandCollection();
}

bool FrameworkListener::onDataAvailable(SocketClient *c) {
    char buffer[255];
    int len;

    if ((len = read(c->getSocket(), buffer, sizeof(buffer) -1)) < 0) {
        LOGE("read() failed (%s)", strerror(errno));
        return errno;
    } else if (!len)
        return false;

    int offset = 0;
    int i;

    for (i = 0; i < len; i++) {
        if (buffer[i] == '\0') {
            dispatchCommand(c, buffer + offset);
            offset = i + 1;
        }
    }
    return true;
}

void FrameworkListener::registerCmd(FrameworkCommand *cmd) {
    mCommands->push_back(cmd);
}

void FrameworkListener::dispatchCommand(SocketClient *cli, char *data) {
    int argc;
    char *argv[FrameworkListener::CMD_ARGS_MAX];

    if (!index(data, '"')) {
        char *next = data;
        char *field;
        int i;

        for (i = 0; (i < FrameworkListener::CMD_ARGS_MAX) &&
                    (argv[i] = strsep(&next, " ")); i++);
        argc = i+1;
    } else {
        LOGD("blehhh not supported");
        return;
    }

    FrameworkCommandCollection::iterator i;

    for (i = mCommands->begin(); i != mCommands->end(); ++i) {
        FrameworkCommand *c = *i;

        if (!strcmp(argv[0], c->getCommand())) {
            if (c->runCommand(cli, argc, argv)) {
                LOGW("Handler '%s' error (%s)", c->getCommand(), strerror(errno));
            }
            return;
        }
    }

    cli->sendMsg(500, "Command not recognized", false);
    return;
}
