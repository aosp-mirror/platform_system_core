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

#ifndef _LOGD_LOG_TIMES_H__
#define _LOGD_LOG_TIMES_H__

#include <pthread.h>
#include <time.h>
#include <sys/types.h>
#include <sysutils/SocketClient.h>
#include <utils/List.h>

class LogReader;

class LogTimeEntry {
    static pthread_mutex_t timesLock;
    unsigned int mRefCount;
    bool mRelease;
    bool mError;
    bool threadRunning;
    pthread_cond_t threadTriggeredCondition;
    pthread_t mThread;
    LogReader &mReader;
    static void *threadStart(void *me);
    static void threadStop(void *me);
    const unsigned int mLogMask;
    const pid_t mPid;
    unsigned int skipAhead;
    unsigned long mCount;
    unsigned long mTail;
    unsigned long mIndex;

public:
    LogTimeEntry(LogReader &reader, SocketClient *client, bool nonBlock,
                 unsigned long tail, unsigned int logMask, pid_t pid,
                 log_time start);

    SocketClient *mClient;
    static const struct timespec EPOCH;
    log_time mStart;
    const bool mNonBlock;
    const log_time mEnd; // only relevant if mNonBlock

    // Protect List manipulations
    static void lock(void) { pthread_mutex_lock(&timesLock); }
    static void unlock(void) { pthread_mutex_unlock(&timesLock); }

    void startReader_Locked(void);

    bool runningReader_Locked(void) const {
        return threadRunning || mRelease || mError || mNonBlock;
    }
    void triggerReader_Locked(void) {
        pthread_cond_signal(&threadTriggeredCondition);
    }

    void triggerSkip_Locked(unsigned int skip) { skipAhead = skip; }

    // Called after LogTimeEntry removed from list, lock implicitly held
    void release_Locked(void) {
        mRelease = true;
        pthread_cond_signal(&threadTriggeredCondition);
        if (mRefCount || threadRunning) {
            return;
        }
        // No one else is holding a reference to this
        delete this;
    }

    // Called to mark socket in jeopardy
    void error_Locked(void) { mError = true; }
    void error(void) { lock(); error_Locked(); unlock(); }

    bool isError_Locked(void) const { return mRelease || mError; }

    // Mark Used
    //  Locking implied, grabbed when protection around loop iteration
    void incRef_Locked(void) { ++mRefCount; }

    bool owned_Locked(void) const { return mRefCount != 0; }

    void decRef_Locked(void) {
        if ((mRefCount && --mRefCount) || !mRelease || threadRunning) {
            return;
        }
        // No one else is holding a reference to this
        delete this;
    }

    // flushTo filter callbacks
    static bool FilterFirstPass(const LogBufferElement *element, void *me);
    static bool FilterSecondPass(const LogBufferElement *element, void *me);
};

typedef android::List<LogTimeEntry *> LastLogTimes;

#endif
