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

#ifndef _LOGD_LOG_BUFFER_H__
#define _LOGD_LOG_BUFFER_H__

#include <sys/types.h>

#include <list>
#include <string>

#include <android/log.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "LogBufferElement.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogTimes.h"
#include "LogWhiteBlackList.h"

//
// We are either in 1970ish (MONOTONIC) or 2016+ish (REALTIME) so to
// differentiate without prejudice, we use 1972 to delineate, earlier
// is likely monotonic, later is real. Otherwise we start using a
// dividing line between monotonic and realtime if more than a minute
// difference between them.
//
namespace android {

static bool isMonotonic(const log_time& mono) {
    static const uint32_t EPOCH_PLUS_2_YEARS = 2 * 24 * 60 * 60 * 1461 / 4;
    static const uint32_t EPOCH_PLUS_MINUTE = 60;

    if (mono.tv_sec >= EPOCH_PLUS_2_YEARS) {
        return false;
    }

    log_time now(CLOCK_REALTIME);

    /* Timezone and ntp time setup? */
    if (now.tv_sec >= EPOCH_PLUS_2_YEARS) {
        return true;
    }

    /* no way to differentiate realtime from monotonic time */
    if (now.tv_sec < EPOCH_PLUS_MINUTE) {
        return false;
    }

    log_time cpu(CLOCK_MONOTONIC);
    /* too close to call to differentiate monotonic times from realtime */
    if ((cpu.tv_sec + EPOCH_PLUS_MINUTE) >= now.tv_sec) {
        return false;
    }

    /* dividing line half way between monotonic and realtime */
    return mono.tv_sec < ((cpu.tv_sec + now.tv_sec) / 2);
}
}

typedef std::list<LogBufferElement*> LogBufferElementCollection;

class LogBuffer {
    LogBufferElementCollection mLogElements;
    pthread_rwlock_t mLogElementsLock;

    LogStatistics stats;

    PruneList mPrune;
    // watermark for last per log id
    LogBufferElementCollection::iterator mLast[LOG_ID_MAX];
    bool mLastSet[LOG_ID_MAX];
    // watermark of any worst/chatty uid processing
    typedef std::unordered_map<uid_t, LogBufferElementCollection::iterator>
        LogBufferIteratorMap;
    LogBufferIteratorMap mLastWorst[LOG_ID_MAX];
    // watermark of any worst/chatty pid of system processing
    typedef std::unordered_map<pid_t, LogBufferElementCollection::iterator>
        LogBufferPidIteratorMap;
    LogBufferPidIteratorMap mLastWorstPidOfSystem[LOG_ID_MAX];

    unsigned long mMaxSize[LOG_ID_MAX];

    bool monotonic;

    LogTags tags;

    LogBufferElement* lastLoggedElements[LOG_ID_MAX];
    LogBufferElement* droppedElements[LOG_ID_MAX];
    void log(LogBufferElement* elem);

   public:
    LastLogTimes& mTimes;

    explicit LogBuffer(LastLogTimes* times);
    ~LogBuffer();
    void init();
    bool isMonotonic() {
        return monotonic;
    }

    int log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid, const char* msg,
            uint16_t len);
    // lastTid is an optional context to help detect if the last previous
    // valid message was from the same source so we can differentiate chatty
    // filter types (identical or expired)
    log_time flushTo(SocketClient* writer, const log_time& start,
                     pid_t* lastTid,  // &lastTid[LOG_ID_MAX] or nullptr
                     bool privileged, bool security,
                     int (*filter)(const LogBufferElement* element,
                                   void* arg) = nullptr,
                     void* arg = nullptr);

    bool clear(log_id_t id, uid_t uid = AID_ROOT);
    unsigned long getSize(log_id_t id);
    int setSize(log_id_t id, unsigned long size);
    unsigned long getSizeUsed(log_id_t id);

    std::string formatStatistics(uid_t uid, pid_t pid, unsigned int logMask);

    void enableStatistics() {
        stats.enableStatistics();
    }

    int initPrune(const char* cp) {
        return mPrune.init(cp);
    }
    std::string formatPrune() {
        return mPrune.format();
    }

    std::string formatGetEventTag(uid_t uid, const char* name,
                                  const char* format) {
        return tags.formatGetEventTag(uid, name, format);
    }
    std::string formatEntry(uint32_t tag, uid_t uid) {
        return tags.formatEntry(tag, uid);
    }
    const char* tagToName(uint32_t tag) {
        return tags.tagToName(tag);
    }

    // helper must be protected directly or implicitly by wrlock()/unlock()
    const char* pidToName(pid_t pid) {
        return stats.pidToName(pid);
    }
    uid_t pidToUid(pid_t pid) { return stats.pidToUid(pid); }
    const char* uidToName(uid_t uid) {
        return stats.uidToName(uid);
    }
    void wrlock() {
        pthread_rwlock_wrlock(&mLogElementsLock);
    }
    void rdlock() {
        pthread_rwlock_rdlock(&mLogElementsLock);
    }
    void unlock() {
        pthread_rwlock_unlock(&mLogElementsLock);
    }

   private:
    static constexpr size_t minPrune = 4;
    static constexpr size_t maxPrune = 256;
    static const log_time pruneMargin;

    void maybePrune(log_id_t id);
    bool isBusy(log_time watermark);
    void kickMe(LogTimeEntry* me, log_id_t id, unsigned long pruneRows);

    bool prune(log_id_t id, unsigned long pruneRows, uid_t uid = AID_ROOT);
    LogBufferElementCollection::iterator erase(
        LogBufferElementCollection::iterator it, bool coalesce = false);
};

#endif  // _LOGD_LOG_BUFFER_H__
