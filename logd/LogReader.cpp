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

#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogReader.h"
#include "LogUtils.h"

static bool CanReadSecurityLogs(SocketClient* client) {
    return client->getUid() == AID_SYSTEM || client->getGid() == AID_SYSTEM;
}

LogReader::LogReader(LogBuffer* logbuf)
    : SocketListener(getLogSocket(), true), mLogbuf(*logbuf) {
}

// When we are notified a new log entry is available, inform
// listening sockets who are watching this entry's log id.
void LogReader::notifyNewLog(unsigned int log_mask) {
    LastLogTimes& times = mLogbuf.mTimes;

    LogReaderThread::wrlock();
    for (const auto& entry : times) {
        if (!entry->IsWatchingMultiple(log_mask)) {
            continue;
        }
        if (entry->timeout().tv_sec || entry->timeout().tv_nsec) {
            continue;
        }
        entry->triggerReader_Locked();
    }
    LogReaderThread::unlock();
}

// Note returning false will release the SocketClient instance.
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

    // Clients are only allowed to send one command, disconnect them if they
    // send another.
    LogReaderThread::wrlock();
    for (const auto& entry : mLogbuf.mTimes) {
        if (entry->client() == cli) {
            entry->release_Locked();
            LogReaderThread::unlock();
            return false;
        }
    }
    LogReaderThread::unlock();

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
        timeout = atol(cp + sizeof(_timeout) - 1) * NS_PER_SEC + log_time(CLOCK_MONOTONIC).nsec();
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
        LogReaderThread::wrlock();
        LogReaderThread::unlock();
        sched_yield();
        nonBlock = true;
    }

    bool privileged = clientHasLogCredentials(cli);
    bool can_read_security = CanReadSecurityLogs(cli);

    uint64_t sequence = 1;
    // Convert realtime to sequence number
    if (start != log_time::EPOCH) {
        bool start_time_set = false;
        uint64_t last = sequence;
        auto log_find_start = [pid, logMask, start, &sequence, &start_time_set,
                               &last](const LogBufferElement* element) -> int {
            if (pid && pid != element->getPid()) {
                return 0;
            }
            if ((logMask & (1 << element->getLogId())) == 0) {
                return 0;
            }
            if (start == element->getRealTime()) {
                sequence = element->getSequence();
                start_time_set = true;
                return -1;
            } else {
                if (start < element->getRealTime()) {
                    sequence = last;
                    start_time_set = true;
                    return -1;
                }
                last = element->getSequence();
            }
            return 0;
        };

        logbuf().flushTo(cli, sequence, nullptr, privileged, can_read_security, log_find_start);

        if (!start_time_set) {
            if (nonBlock) {
                doSocketDelete(cli);
                return false;
            }
            sequence = LogBufferElement::getCurrentSequence();
        }
    }

    android::prdebug(
            "logdr: UID=%d GID=%d PID=%d %c tail=%lu logMask=%x pid=%d "
            "start=%" PRIu64 "ns timeout=%" PRIu64 "ns\n",
            cli->getUid(), cli->getGid(), cli->getPid(), nonBlock ? 'n' : 'b', tail, logMask,
            (int)pid, start.nsec(), timeout);

    if (start == log_time::EPOCH) {
        timeout = 0;
    }

    LogReaderThread::wrlock();
    auto entry =
            std::make_unique<LogReaderThread>(*this, cli, nonBlock, tail, logMask, pid, start,
                                              sequence, timeout, privileged, can_read_security);
    if (!entry->startReader_Locked()) {
        LogReaderThread::unlock();
        return false;
    }

    // release client and entry reference counts once done
    cli->incRef();
    mLogbuf.mTimes.emplace_front(std::move(entry));

    // Set acceptable upper limit to wait for slow reader processing b/27242723
    struct timeval t = { LOGD_SNDTIMEO, 0 };
    setsockopt(cli->getSocket(), SOL_SOCKET, SO_SNDTIMEO, (const char*)&t,
               sizeof(t));

    LogReaderThread::unlock();

    return true;
}

void LogReader::doSocketDelete(SocketClient* cli) {
    LastLogTimes& times = mLogbuf.mTimes;
    LogReaderThread::wrlock();
    LastLogTimes::iterator it = times.begin();
    while (it != times.end()) {
        LogReaderThread* entry = it->get();
        if (entry->client() == cli) {
            entry->release_Locked();
            break;
        }
        it++;
    }
    LogReaderThread::unlock();
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
