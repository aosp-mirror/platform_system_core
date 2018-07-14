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
#include <inttypes.h>
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
// listening sockets who are watching this entry's log id.
void LogReader::notifyNewLog(log_mask_t logMask) {
    FlushCommand command(*this, logMask);
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
        LogTimeEntry::wrlock();
        LogTimeEntry::unlock();
        sched_yield();
        nonBlock = true;
    }

    log_time sequence = start;
    //
    // This somewhat expensive data validation operation is required
    // for non-blocking, with timeout.  The incoming timestamp must be
    // in range of the list, if not, return immediately.  This is
    // used to prevent us from from getting stuck in timeout processing
    // with an invalid time.
    //
    // Find if time is really present in the logs, monotonic or real, implicit
    // conversion from monotonic or real as necessary to perform the check.
    // Exit in the check loop ASAP as you find a transition from older to
    // newer, but use the last entry found to ensure overlap.
    //
    if (nonBlock && (sequence != log_time::EPOCH) && timeout) {
        class LogFindStart {  // A lambda by another name
           private:
            const pid_t mPid;
            const unsigned mLogMask;
            bool mStartTimeSet;
            log_time mStart;
            log_time& mSequence;
            log_time mLast;
            bool mIsMonotonic;

           public:
            LogFindStart(pid_t pid, unsigned logMask, log_time& sequence,
                         bool isMonotonic)
                : mPid(pid),
                  mLogMask(logMask),
                  mStartTimeSet(false),
                  mStart(sequence),
                  mSequence(sequence),
                  mLast(sequence),
                  mIsMonotonic(isMonotonic) {
            }

            static int callback(const LogBufferElement* element, void* obj) {
                LogFindStart* me = reinterpret_cast<LogFindStart*>(obj);
                if ((!me->mPid || (me->mPid == element->getPid())) &&
                    (me->mLogMask & (1 << element->getLogId()))) {
                    log_time real = element->getRealTime();
                    if (me->mStart == real) {
                        me->mSequence = real;
                        me->mStartTimeSet = true;
                        return -1;
                    } else if (!me->mIsMonotonic || android::isMonotonic(real)) {
                        if (me->mStart < real) {
                            me->mSequence = me->mLast;
                            me->mStartTimeSet = true;
                            return -1;
                        }
                        me->mLast = real;
                    } else {
                        me->mLast = real;
                    }
                }
                return false;
            }

            bool found() {
                return mStartTimeSet;
            }

        } logFindStart(pid, logMask, sequence,
                       logbuf().isMonotonic() && android::isMonotonic(start));

        logbuf().flushTo(cli, sequence, nullptr, FlushCommand::hasReadLogs(cli),
                         FlushCommand::hasSecurityLogs(cli),
                         logFindStart.callback, &logFindStart);

        if (!logFindStart.found()) {
            doSocketDelete(cli);
            return false;
        }
    }

    android::prdebug(
        "logdr: UID=%d GID=%d PID=%d %c tail=%lu logMask=%x pid=%d "
        "start=%" PRIu64 "ns timeout=%" PRIu64 "ns\n",
        cli->getUid(), cli->getGid(), cli->getPid(), nonBlock ? 'n' : 'b', tail,
        logMask, (int)pid, sequence.nsec(), timeout);

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
    LogTimeEntry::wrlock();
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
