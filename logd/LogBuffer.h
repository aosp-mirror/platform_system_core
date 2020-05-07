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

#pragma once

#include <sys/types.h>

#include <list>
#include <optional>
#include <string>

#include <android/log.h>
#include <private/android_filesystem_config.h>
#include <sysutils/SocketClient.h>

#include "LogBufferElement.h"
#include "LogReaderThread.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogWhiteBlackList.h"

typedef std::list<LogBufferElement*> LogBufferElementCollection;

class LogBuffer {
    LogBufferElementCollection mLogElements;
    pthread_rwlock_t mLogElementsLock;

    // watermark of any worst/chatty uid processing
    typedef std::unordered_map<uid_t, LogBufferElementCollection::iterator>
        LogBufferIteratorMap;
    LogBufferIteratorMap mLastWorst[LOG_ID_MAX];
    // watermark of any worst/chatty pid of system processing
    typedef std::unordered_map<pid_t, LogBufferElementCollection::iterator>
        LogBufferPidIteratorMap;
    LogBufferPidIteratorMap mLastWorstPidOfSystem[LOG_ID_MAX];

    unsigned long mMaxSize[LOG_ID_MAX];

    LogBufferElement* lastLoggedElements[LOG_ID_MAX];
    LogBufferElement* droppedElements[LOG_ID_MAX];
    void log(LogBufferElement* elem);

   public:
    LastLogTimes& mTimes;

    LogBuffer(LastLogTimes* times, LogTags* tags, PruneList* prune, LogStatistics* stats);
    ~LogBuffer();
    void init();

    int log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid, const char* msg,
            uint16_t len);
    // lastTid is an optional context to help detect if the last previous
    // valid message was from the same source so we can differentiate chatty
    // filter types (identical or expired)
    uint64_t flushTo(SocketClient* writer, uint64_t start,
                     pid_t* lastTid,  // &lastTid[LOG_ID_MAX] or nullptr
                     bool privileged, bool security,
                     const std::function<int(const LogBufferElement* element)>& filter);

    bool clear(log_id_t id, uid_t uid = AID_ROOT);
    unsigned long getSize(log_id_t id);
    int setSize(log_id_t id, unsigned long size);

  private:
    void wrlock() {
        pthread_rwlock_wrlock(&mLogElementsLock);
    }
    void rdlock() {
        pthread_rwlock_rdlock(&mLogElementsLock);
    }
    void unlock() {
        pthread_rwlock_unlock(&mLogElementsLock);
    }

    void maybePrune(log_id_t id);
    void kickMe(LogReaderThread* me, log_id_t id, unsigned long pruneRows);

    bool prune(log_id_t id, unsigned long pruneRows, uid_t uid = AID_ROOT);
    LogBufferElementCollection::iterator erase(
        LogBufferElementCollection::iterator it, bool coalesce = false);

    // Returns an iterator to the oldest element for a given log type, or mLogElements.end() if
    // there are no logs for the given log type. Requires mLogElementsLock to be held.
    LogBufferElementCollection::iterator GetOldest(log_id_t log_id);

    LogTags* tags_;
    PruneList* prune_;
    LogStatistics* stats_;

    // Keeps track of the iterator to the oldest log message of a given log type, as an
    // optimization when pruning logs.  Use GetOldest() to retrieve.
    std::optional<LogBufferElementCollection::iterator> oldest_[LOG_ID_MAX];
};
