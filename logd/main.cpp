/*
 * Copyright (C) 2012-2013 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <linux/prctl.h>

#include "private/android_filesystem_config.h"
#include "CommandListener.h"
#include "LogBuffer.h"
#include "LogListener.h"

static int drop_privs() {
    struct sched_param param;
    memset(&param, 0, sizeof(param));

    if (sched_setscheduler((pid_t) 0, SCHED_BATCH, &param) < 0) {
        return -1;
    }

    if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
        return -1;
    }

    if (setgid(AID_LOGD) != 0) {
        return -1;
    }

    if (setuid(AID_LOGD) != 0) {
        return -1;
    }

    struct __user_cap_header_struct capheader;
    struct __user_cap_data_struct capdata[2];
    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));
    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;

    capdata[CAP_TO_INDEX(CAP_SYSLOG)].permitted = CAP_TO_MASK(CAP_SYSLOG);
    capdata[CAP_TO_INDEX(CAP_SYSLOG)].effective = CAP_TO_MASK(CAP_SYSLOG);
    capdata[0].inheritable = 0;
    capdata[1].inheritable = 0;

    if (capset(&capheader, &capdata[0]) < 0) {
        return -1;
    }

    return 0;
}

// Foreground waits for exit of the three main persistent threads that
// are started here.  The three threads are created to manage UNIX
// domain client sockets for writing, reading and controlling the user
// space logger.  Additional transitory per-client threads are created
// for each reader once they register.
int main() {
    if (drop_privs() != 0) {
        return -1;
    }

    // Serves the purpose of managing the last logs times read on a
    // socket connection, and as a reader lock on a range of log
    // entries.

    LastLogTimes *times = new LastLogTimes();

    // LogBuffer is the object which is responsible for holding all
    // log entries.

    LogBuffer *logBuf = new LogBuffer(times);

    // LogReader listens on /dev/socket/logdr. When a client
    // connects, log entries in the LogBuffer are written to the client.

    LogReader *reader = new LogReader(logBuf);
    if (reader->startListener()) {
        exit(1);
    }

    // LogListener listens on /dev/socket/logdw for client
    // initiated log messages. New log entries are added to LogBuffer
    // and LogReader is notified to send updates to connected clients.

    LogListener *swl = new LogListener(logBuf, reader);
    if (swl->startListener()) {
        exit(1);
    }

    // Command listener listens on /dev/socket/logd for incoming logd
    // administrative commands.

    CommandListener *cl = new CommandListener(logBuf, reader, swl);
    if (cl->startListener()) {
        exit(1);
    }

    pause();
    exit(0);
}

