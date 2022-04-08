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

#include <errno.h>
#include <string.h>
#include <sys/prctl.h>

#include <private/android_logger.h>

#include "FlushCommand.h"
#include "LogBuffer.h"
#include "LogReader.h"
#include "LogTimes.h"

pthread_mutex_t LogTimeEntry::timesLock = PTHREAD_MUTEX_INITIALIZER;

LogTimeEntry::LogTimeEntry(LogReader& reader, SocketClient* client,
                           bool nonBlock, unsigned long tail, log_mask_t logMask,
                           pid_t pid, log_time start, uint64_t timeout)
    : leadingDropped(false),
      mReader(reader),
      mLogMask(logMask),
      mPid(pid),
      mCount(0),
      mTail(tail),
      mIndex(0),
      mClient(client),
      mStart(start),
      mNonBlock(nonBlock),
      mEnd(log_time(android_log_clockid())) {
    mTimeout.tv_sec = timeout / NS_PER_SEC;
    mTimeout.tv_nsec = timeout % NS_PER_SEC;
    memset(mLastTid, 0, sizeof(mLastTid));
    pthread_cond_init(&threadTriggeredCondition, nullptr);
    cleanSkip_Locked();
}

bool LogTimeEntry::startReader_Locked() {
    pthread_attr_t attr;

    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&mThread, &attr, LogTimeEntry::threadStart,
                                this)) {
                pthread_attr_destroy(&attr);
                return true;
            }
        }
        pthread_attr_destroy(&attr);
    }

    return false;
}

void* LogTimeEntry::threadStart(void* obj) {
    prctl(PR_SET_NAME, "logd.reader.per");

    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

    SocketClient* client = me->mClient;

    LogBuffer& logbuf = me->mReader.logbuf();

    bool privileged = FlushCommand::hasReadLogs(client);
    bool security = FlushCommand::hasSecurityLogs(client);

    me->leadingDropped = true;

    wrlock();

    log_time start = me->mStart;

    while (!me->mRelease) {
        if (me->mTimeout.tv_sec || me->mTimeout.tv_nsec) {
            if (pthread_cond_timedwait(&me->threadTriggeredCondition,
                                       &timesLock, &me->mTimeout) == ETIMEDOUT) {
                me->mTimeout.tv_sec = 0;
                me->mTimeout.tv_nsec = 0;
            }
            if (me->mRelease) {
                break;
            }
        }

        unlock();

        if (me->mTail) {
            logbuf.flushTo(client, start, nullptr, privileged, security,
                           FilterFirstPass, me);
            me->leadingDropped = true;
        }
        start = logbuf.flushTo(client, start, me->mLastTid, privileged,
                               security, FilterSecondPass, me);

        wrlock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            break;
        }

        me->mStart = start + log_time(0, 1);

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
    auto it =
        std::find_if(times.begin(), times.end(),
                     [&me](const auto& other) { return other.get() == me; });

    if (it != times.end()) {
        times.erase(it);
    }

    unlock();

    return nullptr;
}

// A first pass to count the number of elements
int LogTimeEntry::FilterFirstPass(const LogBufferElement* element, void* obj) {
    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

    LogTimeEntry::wrlock();

    if (me->leadingDropped) {
        if (element->getDropped()) {
            LogTimeEntry::unlock();
            return false;
        }
        me->leadingDropped = false;
    }

    if (me->mCount == 0) {
        me->mStart = element->getRealTime();
    }

    if ((!me->mPid || (me->mPid == element->getPid())) &&
        (me->isWatching(element->getLogId()))) {
        ++me->mCount;
    }

    LogTimeEntry::unlock();

    return false;
}

// A second pass to send the selected elements
int LogTimeEntry::FilterSecondPass(const LogBufferElement* element, void* obj) {
    LogTimeEntry* me = reinterpret_cast<LogTimeEntry*>(obj);

    LogTimeEntry::wrlock();

    me->mStart = element->getRealTime();

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
        LogTimeEntry::unlock();
        return true;
    }
// FALLTHRU

skip:
    LogTimeEntry::unlock();
    return false;

stop:
    LogTimeEntry::unlock();
    return -1;
}

void LogTimeEntry::cleanSkip_Locked(void) {
    memset(skipAhead, 0, sizeof(skipAhead));
}
