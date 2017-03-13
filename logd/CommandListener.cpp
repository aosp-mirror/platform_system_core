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
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <string>

#include <android-base/stringprintf.h>
#include <cutils/sockets.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "LogCommand.h"
#include "LogUtils.h"

CommandListener::CommandListener(LogBuffer* buf, LogReader* /*reader*/,
                                 LogListener* /*swl*/)
    : FrameworkListener(getLogSocket()) {
    // registerCmd(new ShutdownCmd(buf, writer, swl));
    registerCmd(new ClearCmd(buf));
    registerCmd(new GetBufSizeCmd(buf));
    registerCmd(new SetBufSizeCmd(buf));
    registerCmd(new GetBufSizeUsedCmd(buf));
    registerCmd(new GetStatisticsCmd(buf));
    registerCmd(new SetPruneListCmd(buf));
    registerCmd(new GetPruneListCmd(buf));
    registerCmd(new GetEventTagCmd(buf));
    registerCmd(new ReinitCmd());
    registerCmd(new ExitCmd(this));
}

CommandListener::ShutdownCmd::ShutdownCmd(LogReader* reader, LogListener* swl)
    : LogCommand("shutdown"), mReader(*reader), mSwl(*swl) {
}

int CommandListener::ShutdownCmd::runCommand(SocketClient* /*cli*/,
                                             int /*argc*/, char** /*argv*/) {
    mSwl.stopListener();
    mReader.stopListener();
    exit(0);
}

CommandListener::ClearCmd::ClearCmd(LogBuffer* buf)
    : LogCommand("clear"), mBuf(*buf) {
}

static void setname() {
    static bool name_set;
    if (!name_set) {
        prctl(PR_SET_NAME, "logd.control");
        name_set = true;
    }
}

int CommandListener::ClearCmd::runCommand(SocketClient* cli, int argc,
                                          char** argv) {
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

    cli->sendMsg(mBuf.clear((log_id_t)id, uid) ? "busy" : "success");
    return 0;
}

CommandListener::GetBufSizeCmd::GetBufSizeCmd(LogBuffer* buf)
    : LogCommand("getLogSize"), mBuf(*buf) {
}

int CommandListener::GetBufSizeCmd::runCommand(SocketClient* cli, int argc,
                                               char** argv) {
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

    unsigned long size = mBuf.getSize((log_id_t)id);
    char buf[512];
    snprintf(buf, sizeof(buf), "%lu", size);
    cli->sendMsg(buf);
    return 0;
}

CommandListener::SetBufSizeCmd::SetBufSizeCmd(LogBuffer* buf)
    : LogCommand("setLogSize"), mBuf(*buf) {
}

int CommandListener::SetBufSizeCmd::runCommand(SocketClient* cli, int argc,
                                               char** argv) {
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
    if (mBuf.setSize((log_id_t)id, size)) {
        cli->sendMsg("Range Error");
        return 0;
    }

    cli->sendMsg("success");
    return 0;
}

CommandListener::GetBufSizeUsedCmd::GetBufSizeUsedCmd(LogBuffer* buf)
    : LogCommand("getLogSizeUsed"), mBuf(*buf) {
}

int CommandListener::GetBufSizeUsedCmd::runCommand(SocketClient* cli, int argc,
                                                   char** argv) {
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

    unsigned long size = mBuf.getSizeUsed((log_id_t)id);
    char buf[512];
    snprintf(buf, sizeof(buf), "%lu", size);
    cli->sendMsg(buf);
    return 0;
}

CommandListener::GetStatisticsCmd::GetStatisticsCmd(LogBuffer* buf)
    : LogCommand("getStatistics"), mBuf(*buf) {
}

static std::string package_string(const std::string& str) {
    // Calculate total buffer size prefix, count is the string length w/o nul
    char fmt[32];
    for (size_t l = str.length(), y = 0, x = 6; y != x;
         y = x, x = strlen(fmt) - 2) {
        snprintf(fmt, sizeof(fmt), "%zu\n%%s\n\f", l + x);
    }
    return android::base::StringPrintf(fmt, str.c_str());
}

int CommandListener::GetStatisticsCmd::runCommand(SocketClient* cli, int argc,
                                                  char** argv) {
    setname();
    uid_t uid = cli->getUid();
    if (clientHasLogCredentials(cli)) {
        uid = AID_ROOT;
    }

    unsigned int logMask = -1;
    pid_t pid = 0;
    if (argc > 1) {
        logMask = 0;
        for (int i = 1; i < argc; ++i) {
            static const char _pid[] = "pid=";
            if (!strncmp(argv[i], _pid, sizeof(_pid) - 1)) {
                pid = atol(argv[i] + sizeof(_pid) - 1);
                if (pid == 0) {
                    cli->sendMsg("PID Error");
                    return 0;
                }
                continue;
            }

            int id = atoi(argv[i]);
            if ((id < LOG_ID_MIN) || (LOG_ID_MAX <= id)) {
                cli->sendMsg("Range Error");
                return 0;
            }
            logMask |= 1 << id;
        }
    }

    cli->sendMsg(
        package_string(mBuf.formatStatistics(uid, pid, logMask)).c_str());
    return 0;
}

CommandListener::GetPruneListCmd::GetPruneListCmd(LogBuffer* buf)
    : LogCommand("getPruneList"), mBuf(*buf) {
}

int CommandListener::GetPruneListCmd::runCommand(SocketClient* cli,
                                                 int /*argc*/, char** /*argv*/) {
    setname();
    cli->sendMsg(package_string(mBuf.formatPrune()).c_str());
    return 0;
}

CommandListener::SetPruneListCmd::SetPruneListCmd(LogBuffer* buf)
    : LogCommand("setPruneList"), mBuf(*buf) {
}

int CommandListener::SetPruneListCmd::runCommand(SocketClient* cli, int argc,
                                                 char** argv) {
    setname();
    if (!clientHasLogCredentials(cli)) {
        cli->sendMsg("Permission Denied");
        return 0;
    }

    std::string str;
    for (int i = 1; i < argc; ++i) {
        if (str.length()) {
            str += " ";
        }
        str += argv[i];
    }

    int ret = mBuf.initPrune(str.c_str());

    if (ret) {
        cli->sendMsg("Invalid");
        return 0;
    }

    cli->sendMsg("success");

    return 0;
}

CommandListener::GetEventTagCmd::GetEventTagCmd(LogBuffer* buf)
    : LogCommand("getEventTag"), mBuf(*buf) {
}

int CommandListener::GetEventTagCmd::runCommand(SocketClient* cli, int argc,
                                                char** argv) {
    setname();
    uid_t uid = cli->getUid();
    if (clientHasLogCredentials(cli)) {
        uid = AID_ROOT;
    }

    const char* name = NULL;
    const char* format = NULL;
    const char* id = NULL;
    for (int i = 1; i < argc; ++i) {
        static const char _name[] = "name=";
        if (!strncmp(argv[i], _name, strlen(_name))) {
            name = argv[i] + strlen(_name);
            continue;
        }

        static const char _format[] = "format=";
        if (!strncmp(argv[i], _format, strlen(_format))) {
            format = argv[i] + strlen(_format);
            continue;
        }

        static const char _id[] = "id=";
        if (!strncmp(argv[i], _id, strlen(_id))) {
            id = argv[i] + strlen(_id);
            continue;
        }
    }

    if (id) {
        if (format || name) {
            cli->sendMsg("can not mix id= with either format= or name=");
            return 0;
        }
        cli->sendMsg(package_string(mBuf.formatEntry(atoi(id), uid)).c_str());
        return 0;
    }

    cli->sendMsg(
        package_string(mBuf.formatGetEventTag(uid, name, format)).c_str());

    return 0;
}

CommandListener::ReinitCmd::ReinitCmd() : LogCommand("reinit") {
}

int CommandListener::ReinitCmd::runCommand(SocketClient* cli, int /*argc*/,
                                           char** /*argv*/) {
    setname();

    reinit_signal_handler(SIGHUP);

    cli->sendMsg("success");

    return 0;
}

CommandListener::ExitCmd::ExitCmd(CommandListener* parent)
    : LogCommand("EXIT"), mParent(*parent) {
}

int CommandListener::ExitCmd::runCommand(SocketClient* cli, int /*argc*/,
                                         char** /*argv*/) {
    setname();

    cli->sendMsg("success");
    release(cli);

    return 0;
}

int CommandListener::getLogSocket() {
    static const char socketName[] = "logd";
    int sock = android_get_control_socket(socketName);

    if (sock < 0) {
        sock = socket_local_server(
            socketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    }

    return sock;
}
