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
#include <stdlib.h>

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

    len = TEMP_FAILURE_RETRY(read(c->getSocket(), buffer, sizeof(buffer)));
    if (len < 0) {
        SLOGE("read() failed (%s)", strerror(errno));
        return false;
    } else if (!len)
        return false;

    int offset = 0;
    int i;

    for (i = 0; i < len; i++) {
        if (buffer[i] == '\0') {
            /* IMPORTANT: dispatchCommand() expects a zero-terminated string */
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
    FrameworkCommandCollection::iterator i;
    int argc = 0;
    char *argv[FrameworkListener::CMD_ARGS_MAX];
    char tmp[255];
    char *p = data;
    char *q = tmp;
    char *qlimit = tmp + sizeof(tmp) - 1;
    bool esc = false;
    bool quote = false;
    int k;

    memset(argv, 0, sizeof(argv));
    memset(tmp, 0, sizeof(tmp));
    while(*p) {
        if (*p == '\\') {
            if (esc) {
                if (q >= qlimit)
                    goto overflow;
                *q++ = '\\';
                esc = false;
            } else
                esc = true;
            p++;
            continue;
        } else if (esc) {
            if (*p == '"') {
                if (q >= qlimit)
                    goto overflow;
                *q++ = '"';
            } else if (*p == '\\') {
                if (q >= qlimit)
                    goto overflow;
                *q++ = '\\';
            } else {
                cli->sendMsg(500, "Unsupported escape sequence", false);
                goto out;
            }
            p++;
            esc = false;
            continue;
        }

        if (*p == '"') {
            if (quote)
                quote = false;
            else
                quote = true;
            p++;
            continue;
        }

        if (q >= qlimit)
            goto overflow;
        *q = *p++;
        if (!quote && *q == ' ') {
            *q = '\0';
            if (argc >= CMD_ARGS_MAX)
                goto overflow;
            argv[argc++] = strdup(tmp);
            memset(tmp, 0, sizeof(tmp));
            q = tmp;
            continue;
        }
        q++;
    }

    *q = '\0';
    if (argc >= CMD_ARGS_MAX)
        goto overflow;
    argv[argc++] = strdup(tmp);
#if 0
    for (k = 0; k < argc; k++) {
        SLOGD("arg[%d] = '%s'", k, argv[k]);
    }
#endif

    if (quote) {
        cli->sendMsg(500, "Unclosed quotes error", false);
        goto out;
    }

    for (i = mCommands->begin(); i != mCommands->end(); ++i) {
        FrameworkCommand *c = *i;

        if (!strcmp(argv[0], c->getCommand())) {
            if (c->runCommand(cli, argc, argv)) {
                SLOGW("Handler '%s' error (%s)", c->getCommand(), strerror(errno));
            }
            goto out;
        }
    }

    cli->sendMsg(500, "Command not recognized", false);
out:
    int j;
    for (j = 0; j < argc; j++)
        free(argv[j]);
    return;

overflow:
    cli->sendMsg(500, "Command too long", false);
    goto out;
}
