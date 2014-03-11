/*
 * Copyright (C) 2012-2014 The Android Open Source Project
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

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "LogCommand.h"

CommandListener::CommandListener(LogBuffer *buf, LogReader * /*reader*/,
                                 LogListener * /*swl*/)
        : FrameworkListener("logd")
        , mBuf(*buf) {
    // registerCmd(new ShutdownCmd(buf, writer, swl));
    registerCmd(new ClearCmd(buf));
    registerCmd(new GetBufSizeCmd(buf));
    registerCmd(new GetBufSizeUsedCmd(buf));
}

CommandListener::ShutdownCmd::ShutdownCmd(LogBuffer *buf, LogReader *reader,
                                          LogListener *swl)
        : LogCommand("shutdown")
        , mBuf(*buf)
        , mReader(*reader)
        , mSwl(*swl)
{ }

int CommandListener::ShutdownCmd::runCommand(SocketClient * /*cli*/,
                                             int /*argc*/,
                                             char ** /*argv*/) {
    mSwl.stopListener();
    mReader.stopListener();
    exit(0);
}

CommandListener::ClearCmd::ClearCmd(LogBuffer *buf)
        : LogCommand("clear")
        , mBuf(*buf)
{ }

int CommandListener::ClearCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    if (!clientHasLogCredentials(cli)) {
        cli->sendMsg("Permission Denied");
        return 0;
    }

    if (argc < 2) {
        cli->sendMsg("Missing Argument");
        return 0;
    }

    int id = atoi(argv[1]);
    if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
        cli->sendMsg("Range Error");
        return 0;
    }

    mBuf.clear((log_id_t) id);
    cli->sendMsg("success");
    return 0;
}

CommandListener::GetBufSizeCmd::GetBufSizeCmd(LogBuffer *buf)
        : LogCommand("getLogSize")
        , mBuf(*buf)
{ }

int CommandListener::GetBufSizeCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg("Missing Argument");
        return 0;
    }

    int id = atoi(argv[1]);
    if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
        cli->sendMsg("Range Error");
        return 0;
    }

    unsigned long size = mBuf.getSize((log_id_t) id);
    char buf[512];
    snprintf(buf, sizeof(buf), "%lu", size);
    cli->sendMsg(buf);
    return 0;
}

CommandListener::GetBufSizeUsedCmd::GetBufSizeUsedCmd(LogBuffer *buf)
        : LogCommand("getLogSizeUsed")
        , mBuf(*buf)
{ }

int CommandListener::GetBufSizeUsedCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    if (argc < 2) {
        cli->sendMsg("Missing Argument");
        return 0;
    }

    int id = atoi(argv[1]);
    if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
        cli->sendMsg("Range Error");
        return 0;
    }

    unsigned long size = mBuf.getSizeUsed((log_id_t) id);
    char buf[512];
    snprintf(buf, sizeof(buf), "%lu", size);
    cli->sendMsg(buf);
    return 0;
}
