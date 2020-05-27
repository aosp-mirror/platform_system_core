/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <atomic>
#include <list>
#include <mutex>

#include "LogBuffer.h"
#include "LogBufferElement.h"
#include "LogReaderList.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "rwlock.h"

class SimpleLogBuffer : public LogBuffer {
  public:
    SimpleLogBuffer(LogReaderList* reader_list, LogTags* tags, LogStatistics* stats);
    ~SimpleLogBuffer();
    void Init() override;

    int Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid, const char* msg,
            uint16_t len) override;
    uint64_t FlushTo(
            LogWriter* writer, uint64_t start, pid_t* lastTid,
            const std::function<FilterResult(const LogBufferElement* element)>& filter) override;

    bool Clear(log_id_t id, uid_t uid) override;
    unsigned long GetSize(log_id_t id) override;
    int SetSize(log_id_t id, unsigned long size) override;

    uint64_t sequence() const override { return sequence_.load(std::memory_order_relaxed); }

  protected:
    virtual bool Prune(log_id_t id, unsigned long prune_rows, uid_t uid) REQUIRES(lock_);
    virtual void LogInternal(LogBufferElement&& elem) REQUIRES(lock_);

    // Returns an iterator to the oldest element for a given log type, or logs_.end() if
    // there are no logs for the given log type. Requires logs_lock_ to be held.
    std::list<LogBufferElement>::iterator GetOldest(log_id_t log_id) REQUIRES(lock_);
    std::list<LogBufferElement>::iterator Erase(std::list<LogBufferElement>::iterator it)
            REQUIRES(lock_);
    void KickReader(LogReaderThread* reader, log_id_t id, unsigned long prune_rows)
            REQUIRES_SHARED(lock_);

    LogStatistics* stats() { return stats_; }
    LogReaderList* reader_list() { return reader_list_; }
    unsigned long max_size(log_id_t id) REQUIRES_SHARED(lock_) { return max_size_[id]; }
    std::list<LogBufferElement>& logs() { return logs_; }

    RwLock lock_;

  private:
    bool ShouldLog(log_id_t log_id, const char* msg, uint16_t len);
    void MaybePrune(log_id_t id) REQUIRES(lock_);

    LogReaderList* reader_list_;
    LogTags* tags_;
    LogStatistics* stats_;

    std::atomic<uint64_t> sequence_ = 1;

    unsigned long max_size_[LOG_ID_MAX] GUARDED_BY(lock_);
    std::list<LogBufferElement> logs_ GUARDED_BY(lock_);
    // Keeps track of the iterator to the oldest log message of a given log type, as an
    // optimization when pruning logs.  Use GetOldest() to retrieve.
    std::optional<std::list<LogBufferElement>::iterator> oldest_[LOG_ID_MAX] GUARDED_BY(lock_);
};
