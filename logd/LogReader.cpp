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

#include <ctype.h>
#include <poll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cutils/sockets.h>
#include <private/android_logger.h>

#include "FlushCommand.h"
#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogReader.h"
#include "LogUtils.h"

LogReader::LogReader(LogBuffer* logbuf)
    : SocketListener(getLogSocket(), true), mLogbuf(*logbuf) {
}

// When we are notified a new log entry is available, inform
// all of our listening sockets.
void LogReader::notifyNewLog() {
    FlushCommand command(*this);
    runOnEachSocket(&command);
}

bool LogReader::onDataAvailable(SocketClient* cli) {
    static bool name_set;
    if (!name_set) {
        prctl(PR_SET_NAME, "logd.reader");
        name_set = true;
    }

    char buffer[255];

    int len = read(cli->getSocket(), buffer, sizeof(buffer) - 1);
    if (len <= 0) {
        doSocketDelete(cli);
        return false;
    }
    buffer[len] = '\0';

    unsigned long tail = 0;
    static const char _tail[] = " tail=";
    char* cp = strstr(buffer, _tail);
    if (cp) {
        tail = atol(cp + sizeof(_tail) - 1);
    }

    log_time start(log_time::EPOCH);
    static const char _start[] = " start=";
    cp = strstr(buffer, _start);
    if (cp) {
        // Parse errors will result in current time
        start.strptime(cp + sizeof(_start) - 1, "%s.%q");
    }

    uint64_t timeout = 0;
    static const char _timeout[] = " timeout=";
    cp = strstr(buffer, _timeout);
    if (cp) {
        timeout = atol(cp + sizeof(_timeout) - 1) * NS_PER_SEC +
                  log_time(CLOCK_REALTIME).nsec();
    }

    unsigned int logMask = -1;
    static const char _logIds[] = " lids=";
    cp = strstr(buffer, _logIds);
    if (cp) {
        logMask = 0;
        cp += sizeof(_logIds) - 1;
        while (*cp && *cp != '\0') {
            int val = 0;
            while (isdigit(*cp)) {
                val = val * 10 + *cp - '0';
                ++cp;
            }
            logMask |= 1 << val;
            if (*cp != ',') {
                break;
            }
            ++cp;
        }
    }

    pid_t pid = 0;
    static const char _pid[] = " pid=";
    cp = strstr(buffer, _pid);
    if (cp) {
        pid = atol(cp + sizeof(_pid) - 1);
    }

    bool nonBlock = false;
    if (!fastcmp<strncmp>(buffer, "dumpAndClose", 12)) {
        // Allow writer to get some cycles, and wait for pending notifications
        sched_yield();
        LogTimeEntry::lock();
        LogTimeEntry::unlock();
        sched_yield();
        nonBlock = true;
    }

    uint64_t sequence = 1;
    // Convert realtime to sequence number
    if (start != log_time::EPOCH) {
        class LogFindStart {
            const pid_t mPid;
            const unsigned mLogMask;
            bool startTimeSet;
            log_time& start;
            uint64_t& sequence;
            uint64_t last;
            bool isMonotonic;

           public:
            LogFindStart(unsigned logMask, pid_t pid, log_time& start,
                         uint64_t& sequence, bool isMonotonic)
                : mPid(pid),
                  mLogMask(logMask),
                  startTimeSet(false),
                  start(start),
                  sequence(sequence),
                  last(sequence),
                  isMonotonic(isMonotonic) {
            }

            static int callback(const LogBufferElement* element, void* obj) {
                LogFindStart* me = reinterpret_cast<LogFindStart*>(obj);
                if ((!me->mPid || (me->mPid == element->getPid())) &&
                    (me->mLogMask & (1 << element->getLogId()))) {
                    if (me->start == element->getRealTime()) {
                        me->sequence = element->getSequence();
                        me->startTimeSet = true;
                        return -1;
                    } else if (!me->isMonotonic ||
                               android::isMonotonic(element->getRealTime())) {
                        if (me->start < element->getRealTime()) {
                            me->sequence = me->last;
                            me->startTimeSet = true;
                            return -1;
                        }
                        me->last = element->getSequence();
                    } else {
                        me->last = element->getSequence();
                    }
                }
                return false;
            }

            bool found() {
                return startTimeSet;
            }
        } logFindStart(logMask, pid, start, sequence,
                       logbuf().isMonotonic() && android::isMonotonic(start));

        logbuf().flushTo(cli, sequence, FlushCommand::hasReadLogs(cli),
                         FlushCommand::hasSecurityLogs(cli),
                         logFindStart.callback, &logFindStart);

        if (!logFindStart.found()) {
            if (nonBlock) {
                doSocketDelete(cli);
                return false;
            }
            sequence = LogBufferElement::getCurrentSequence();
        }
    }

    FlushCommand command(*this, nonBlock, tail, logMask, pid, sequence, timeout);

    // Set acceptable upper limit to wait for slow reader processing b/27242723
    struct timeval t = { LOGD_SNDTIMEO, 0 };
    setsockopt(cli->getSocket(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&t,
               sizeof(t));

    command.runSocketCommand(cli);
    return true;
}

void LogReader::doSocketDelete(SocketClient* cli) {
    LastLogTimes& times = mLogbuf.mTimes;
    LogTimeEntry::lock();
    LastLogTimes::iterator it = times.begin();
    while (it != times.end()) {
        LogTimeEntry* entry = (*it);
        if (entry->mClient == cli) {
            times.erase(it);
            entry->release_Locked();
            break;
        }
        it++;
    }
    LogTimeEntry::unlock();
}

int LogReader::getLogSocket() {
    static const char socketName[] = "logdr";
    int sock = android_get_control_socket(socketName);

    if (sock < 0) {
        sock = socket_local_server(
            socketName, ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET);
    }

    return sock;
}
