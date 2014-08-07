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

#include <sys/prctl.h>

#include "FlushCommand.h"
#include "LogBuffer.h"
#include "LogTimes.h"
#include "LogReader.h"

pthread_mutex_t LogTimeEntry::timesLock = PTHREAD_MUTEX_INITIALIZER;

const struct timespec LogTimeEntry::EPOCH = { 0, 1 };

LogTimeEntry::LogTimeEntry(LogReader &reader, SocketClient *client,
                           bool nonBlock, unsigned long tail,
                           unsigned int logMask, pid_t pid,
                           log_time start)
        : mRefCount(1)
        , mRelease(false)
        , mError(false)
        , threadRunning(false)
        , mReader(reader)
        , mLogMask(logMask)
        , mPid(pid)
        , skipAhead(0)
        , mCount(0)
        , mTail(tail)
        , mIndex(0)
        , mClient(client)
        , mStart(start)
        , mNonBlock(nonBlock)
        , mEnd(CLOCK_MONOTONIC)
{
        pthread_cond_init(&threadTriggeredCondition, NULL);
}

void LogTimeEntry::startReader_Locked(void) {
    pthread_attr_t attr;

    threadRunning = true;

    if (!pthread_attr_init(&attr)) {
        if (!pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
            if (!pthread_create(&mThread, &attr,
                                LogTimeEntry::threadStart, this)) {
                pthread_attr_destroy(&attr);
                return;
            }
        }
        pthread_attr_destroy(&attr);
    }
    threadRunning = false;
    if (mClient) {
        mClient->decRef();
    }
    decRef_Locked();
}

void LogTimeEntry::threadStop(void *obj) {
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    lock();

    if (me->mNonBlock) {
        me->error_Locked();
    }

    SocketClient *client = me->mClient;

    if (me->isError_Locked()) {
        LogReader &reader = me->mReader;
        LastLogTimes &times = reader.logbuf().mTimes;

        LastLogTimes::iterator it = times.begin();
        while(it != times.end()) {
            if (*it == me) {
                times.erase(it);
                me->release_Locked();
                break;
            }
            it++;
        }

        me->mClient = NULL;
        reader.release(client);
    }

    if (client) {
        client->decRef();
    }

    me->threadRunning = false;
    me->decRef_Locked();

    unlock();
}

void *LogTimeEntry::threadStart(void *obj) {
    prctl(PR_SET_NAME, "logd.reader.per");

    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    pthread_cleanup_push(threadStop, obj);

    SocketClient *client = me->mClient;
    if (!client) {
        me->error();
        return NULL;
    }

    LogBuffer &logbuf = me->mReader.logbuf();

    bool privileged = FlushCommand::hasReadLogs(client);

    lock();

    while (me->threadRunning && !me->isError_Locked()) {
        log_time start = me->mStart;

        unlock();

        if (me->mTail) {
            logbuf.flushTo(client, start, privileged, FilterFirstPass, me);
        }
        start = logbuf.flushTo(client, start, privileged, FilterSecondPass, me);

        lock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            me->error_Locked();
        }

        if (me->mNonBlock || !me->threadRunning || me->isError_Locked()) {
            break;
        }

        pthread_cond_wait(&me->threadTriggeredCondition, &timesLock);
    }

    unlock();

    pthread_cleanup_pop(true);

    return NULL;
}

// A first pass to count the number of elements
bool LogTimeEntry::FilterFirstPass(const LogBufferElement *element, void *obj) {
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    LogTimeEntry::lock();

    if (me->mCount == 0) {
        me->mStart = element->getMonotonicTime();
    }

    if ((!me->mPid || (me->mPid == element->getPid()))
            && (me->mLogMask & (1 << element->getLogId()))) {
        ++me->mCount;
    }

    LogTimeEntry::unlock();

    return false;
}

// A second pass to send the selected elements
bool LogTimeEntry::FilterSecondPass(const LogBufferElement *element, void *obj) {
    LogTimeEntry *me = reinterpret_cast<LogTimeEntry *>(obj);

    LogTimeEntry::lock();

    if (me->skipAhead) {
        me->skipAhead--;
        goto skip;
    }

    me->mStart = element->getMonotonicTime();

    // Truncate to close race between first and second pass
    if (me->mNonBlock && me->mTail && (me->mIndex >= me->mCount)) {
        goto skip;
    }

    if ((me->mLogMask & (1 << element->getLogId())) == 0) {
        goto skip;
    }

    if (me->mPid && (me->mPid != element->getPid())) {
        goto skip;
    }

    if (me->isError_Locked()) {
        goto skip;
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
    if (!me->skipAhead) {
        LogTimeEntry::unlock();
        return true;
    }
    // FALLTHRU

skip:
    LogTimeEntry::unlock();
    return false;
}
