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
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "LogCommand.h"

CommandListener::CommandListener(LogBuffer *buf, LogReader * /*reader*/,
                                 LogListener * /*swl*/) :
        FrameworkListener(getLogSocket()),
        mBuf(*buf) {
    // registerCmd(new ShutdownCmd(buf, writer, swl));
    registerCmd(new ClearCmd(buf));
    registerCmd(new GetBufSizeCmd(buf));
    registerCmd(new SetBufSizeCmd(buf));
    registerCmd(new GetBufSizeUsedCmd(buf));
    registerCmd(new GetStatisticsCmd(buf));
    registerCmd(new SetPruneListCmd(buf));
    registerCmd(new GetPruneListCmd(buf));
    registerCmd(new ReinitCmd());
}

CommandListener::ShutdownCmd::ShutdownCmd(LogBuffer *buf, LogReader *reader,
                                          LogListener *swl) :
        LogCommand("shutdown"),
        mBuf(*buf),
        mReader(*reader),
        mSwl(*swl) {
}

int CommandListener::ShutdownCmd::runCommand(SocketClient * /*cli*/,
                                             int /*argc*/,
                                             char ** /*argv*/) {
    mSwl.stopListener();
    mReader.stopListener();
    exit(0);
}

CommandListener::ClearCmd::ClearCmd(LogBuffer *buf) :
        LogCommand("clear"),
        mBuf(*buf) {
}

static void setname() {
    static bool name_set;
    if (!name_set) {
        prctl(PR_SET_NAME, "logd.control");
        name_set = true;
    }
}

int CommandListener::ClearCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    setname();
    uid_t uid = cli->getUid();
    if (clientHasLogCredentials(cli)) {
        uid = AID_ROOT;
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

    mBuf.clear((log_id_t) id, uid);
    cli->sendMsg("success");
    return 0;
}

CommandListener::GetBufSizeCmd::GetBufSizeCmd(LogBuffer *buf) :
        LogCommand("getLogSize"),
        mBuf(*buf) {
}

int CommandListener::GetBufSizeCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    setname();
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

CommandListener::SetBufSizeCmd::SetBufSizeCmd(LogBuffer *buf) :
        LogCommand("setLogSize"),
        mBuf(*buf) {
}

int CommandListener::SetBufSizeCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    setname();
    if (!clientHasLogCredentials(cli)) {
        cli->sendMsg("Permission Denied");
        return 0;
    }

    if (argc < 3) {
        cli->sendMsg("Missing Argument");
        return 0;
    }

    int id = atoi(argv[1]);
    if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
        cli->sendMsg("Range Error");
        return 0;
    }

    unsigned long size = atol(argv[2]);
    if (mBuf.setSize((log_id_t) id, size)) {
        cli->sendMsg("Range Error");
        return 0;
    }

    cli->sendMsg("success");
    return 0;
}

CommandListener::GetBufSizeUsedCmd::GetBufSizeUsedCmd(LogBuffer *buf) :
        LogCommand("getLogSizeUsed"),
        mBuf(*buf) {
}

int CommandListener::GetBufSizeUsedCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    setname();
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

CommandListener::GetStatisticsCmd::GetStatisticsCmd(LogBuffer *buf) :
        LogCommand("getStatistics"),
        mBuf(*buf) {
}

static void package_string(char **strp) {
    const char *a = *strp;
    if (!a) {
        a = "";
    }

    // Calculate total buffer size prefix, count is the string length w/o nul
    char fmt[32];
    for(size_t l = strlen(a), y = 0, x = 6; y != x; y = x, x = strlen(fmt) - 2) {
        snprintf(fmt, sizeof(fmt), "%zu\n%%s\n\f", l + x);
    }

    char *b = *strp;
    *strp = NULL;
    asprintf(strp, fmt, a);
    free(b);
}

int CommandListener::GetStatisticsCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    setname();
    uid_t uid = cli->getUid();
    if (clientHasLogCredentials(cli)) {
        uid = AID_ROOT;
    }

    unsigned int logMask = -1;
    if (argc > 1) {
        logMask = 0;
        for (int i = 1; i < argc; ++i) {
            int id = atoi(argv[i]);
            if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
                cli->sendMsg("Range Error");
                return 0;
            }
            logMask |= 1 << id;
        }
    }

    char *buf = NULL;

    mBuf.formatStatistics(&buf, uid, logMask);
    if (!buf) {
        cli->sendMsg("Failed");
    } else {
        package_string(&buf);
        cli->sendMsg(buf);
        free(buf);
    }
    return 0;
}

CommandListener::GetPruneListCmd::GetPruneListCmd(LogBuffer *buf) :
        LogCommand("getPruneList"),
        mBuf(*buf) {
}

int CommandListener::GetPruneListCmd::runCommand(SocketClient *cli,
                                         int /*argc*/, char ** /*argv*/) {
    setname();
    char *buf = NULL;
    mBuf.formatPrune(&buf);
    if (!buf) {
        cli->sendMsg("Failed");
    } else {
        package_string(&buf);
        cli->sendMsg(buf);
        free(buf);
    }
    return 0;
}

CommandListener::SetPruneListCmd::SetPruneListCmd(LogBuffer *buf) :
        LogCommand("setPruneList"),
        mBuf(*buf) {
}

int CommandListener::SetPruneListCmd::runCommand(SocketClient *cli,
                                         int argc, char **argv) {
    setname();
    if (!clientHasLogCredentials(cli)) {
        cli->sendMsg("Permission Denied");
        return 0;
    }

    char *cp = NULL;
    for (int i = 1; i < argc; ++i) {
        char *p = cp;
        if (p) {
            cp = NULL;
            asprintf(&cp, "%s %s", p, argv[i]);
            free(p);
        } else {
            asprintf(&cp, "%s", argv[i]);
        }
    }

    int ret = mBuf.initPrune(cp);
    free(cp);

    if (ret) {
        cli->sendMsg("Invalid");
        return 0;
    }

    cli->sendMsg("success");

    return 0;
}

CommandListener::ReinitCmd::ReinitCmd() : LogCommand("reinit") {
}

int CommandListener::ReinitCmd::runCommand(SocketClient *cli,
                                         int /*argc*/, char ** /*argv*/) {
    setname();

    reinit_signal_handler(SIGHUP);

    cli->sendMsg("success");

    return 0;
}

int CommandListener::getLogSocket() {
    static const char socketName[] = "logd";
    int sock = android_get_control_socket(socketName);

    if (sock < 0) {
        sock = socket_local_server(socketName,
                                   ANDROID_SOCKET_NAMESPACE_RESERVED,
                                   SOCK_STREAM);
    }

    return sock;
}
