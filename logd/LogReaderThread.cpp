/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "LogReaderThread.h"

#include <errno.h>
#include <string.h>
#include <sys/prctl.h>

#include "LogBuffer.h"
#include "LogReader.h"

pthread_mutex_t LogReaderThread::timesLock = PTHREAD_MUTEX_INITIALIZER;

LogReaderThread::LogReaderThread(LogReader& reader, SocketClient* client, bool non_block,
                                 unsigned long tail, log_mask_t log_mask, pid_t pid,
                                 log_time start_time, uint64_t start, uint64_t timeout,
                                 bool privileged, bool can_read_security_logs)
    : leadingDropped(false),
      mReader(reader),
      mLogMask(log_mask),
      mPid(pid),
      mCount(0),
      mTail(tail),
      mIndex(0),
      mClient(client),
      mStartTime(start_time),
      mStart(start),
      mNonBlock(non_block),
      privileged_(privileged),
      can_read_security_logs_(can_read_security_logs) {
    mTimeout.tv_sec = timeout / NS_PER_SEC;
    mTimeout.tv_nsec = timeout % NS_PER_SEC;
    memset(mLastTid, 0, sizeof(mLastTid));
    pthread_cond_init(&threadTriggeredCondition, nullptr);
    cleanSkip_Locked();
}

bool LogReaderThread::startReader_Locked() {
    pthread_attr_t attr;

    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&mThread, &attr, LogReaderThread::threadStart, this)) {
                pthread_attr_destroy(&attr);
                return true;
            }
        }
        pthread_attr_destroy(&attr);
    }

    return false;
}

void* LogReaderThread::threadStart(void* obj) {
    prctl(PR_SET_NAME, "logd.reader.per");

    LogReaderThread* me = reinterpret_cast<LogReaderThread*>(obj);

    SocketClient* client = me->mClient;

    LogBuffer& logbuf = me->mReader.logbuf();

    me->leadingDropped = true;

    wrlock();

    uint64_t start = me->mStart;

    while (!me->mRelease) {
        if (me->mTimeout.tv_sec || me->mTimeout.tv_nsec) {
            if (pthread_cond_clockwait(&me->threadTriggeredCondition, &timesLock, CLOCK_MONOTONIC,
                                       &me->mTimeout) == ETIMEDOUT) {
                me->mTimeout.tv_sec = 0;
                me->mTimeout.tv_nsec = 0;
            }
            if (me->mRelease) {
                break;
            }
        }

        unlock();

        if (me->mTail) {
            logbuf.flushTo(client, start, nullptr, me->privileged_, me->can_read_security_logs_,
                           FilterFirstPass, me);
            me->leadingDropped = true;
        }
        start = logbuf.flushTo(client, start, me->mLastTid, me->privileged_,
                               me->can_read_security_logs_, FilterSecondPass, me);

        // We only ignore entries before the original start time for the first flushTo(), if we
        // get entries after this first flush before the original start time, then the client
        // wouldn't have seen them.
        // Note: this is still racy and may skip out of order events that came in since the last
        // time the client disconnected and then reconnected with the new start time.  The long term
        // solution here is that clients must request events since a specific sequence number.
        me->mStartTime.tv_sec = 0;
        me->mStartTime.tv_nsec = 0;

        wrlock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            break;
        }

        me->mStart = start + 1;

        if (me->mNonBlock || me->mRelease) {
            break;
        }

        me->cleanSkip_Locked();

        if (!me->mTimeout.tv_sec && !me->mTimeout.tv_nsec) {
            pthread_cond_wait(&me->threadTriggeredCondition, &timesLock);
        }
    }

    LogReader& reader = me->mReader;
    reader.release(client);

    client->decRef();

    LastLogTimes& times = reader.logbuf().mTimes;
    auto it = std::find_if(times.begin(), times.end(),
                           [&me](const auto& other) { return other.get() == me; });

    if (it != times.end()) {
        times.erase(it);
    }

    unlock();

    return nullptr;
}

// A first pass to count the number of elements
int LogReaderThread::FilterFirstPass(const LogBufferElement* element, void* obj) {
    LogReaderThread* me = reinterpret_cast<LogReaderThread*>(obj);

    LogReaderThread::wrlock();

    if (me->leadingDropped) {
        if (element->getDropped()) {
            LogReaderThread::unlock();
            return false;
        }
        me->leadingDropped = false;
    }

    if (me->mCount == 0) {
        me->mStart = element->getSequence();
    }

    if ((!me->mPid || me->mPid == element->getPid()) && me->isWatching(element->getLogId()) &&
        (me->mStartTime == log_time::EPOCH || me->mStartTime <= element->getRealTime())) {
        ++me->mCount;
    }

    LogReaderThread::unlock();

    return false;
}

// A second pass to send the selected elements
int LogReaderThread::FilterSecondPass(const LogBufferElement* element, void* obj) {
    LogReaderThread* me = reinterpret_cast<LogReaderThread*>(obj);

    LogReaderThread::wrlock();

    me->mStart = element->getSequence();

    if (me->skipAhead[element->getLogId()]) {
        me->skipAhead[element->getLogId()]--;
        goto skip;
    }

    if (me->leadingDropped) {
        if (element->getDropped()) {
            goto skip;
        }
        me->leadingDropped = false;
    }

    // Truncate to close race between first and second pass
    if (me->mNonBlock && me->mTail && (me->mIndex >= me->mCount)) {
        goto stop;
    }

    if (!me->isWatching(element->getLogId())) {
        goto skip;
    }

    if (me->mPid && (me->mPid != element->getPid())) {
        goto skip;
    }

    if (me->mStartTime != log_time::EPOCH && element->getRealTime() <= me->mStartTime) {
        goto skip;
    }

    if (me->mRelease) {
        goto stop;
    }

    if (!me->mTail) {
        goto ok;
    }

    ++me->mIndex;

    if ((me->mCount > me->mTail) && (me->mIndex <= (me->mCount - me->mTail))) {
        goto skip;
    }

    if (!me->mNonBlock) {
        me->mTail = 0;
    }

ok:
    if (!me->skipAhead[element->getLogId()]) {
        LogReaderThread::unlock();
        return true;
    }
    // FALLTHRU

skip:
    LogReaderThread::unlock();
    return false;

stop:
    LogReaderThread::unlock();
    return -1;
}

void LogReaderThread::cleanSkip_Locked(void) {
    memset(skipAhead, 0, sizeof(skipAhead));
}
