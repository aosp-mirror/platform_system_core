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
#include <bitset>
#include <list>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

#include <android-base/thread_annotations.h>

#include "LogBuffer.h"
#include "LogReaderList.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "SerializedLogChunk.h"
#include "SerializedLogEntry.h"
#include "rwlock.h"

class SerializedLogBuffer final : public LogBuffer {
  public:
    SerializedLogBuffer(LogReaderList* reader_list, LogTags* tags, LogStatistics* stats);
    void Init() override;

    int Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid, const char* msg,
            uint16_t len) override;
    std::unique_ptr<FlushToState> CreateFlushToState(uint64_t start, LogMask log_mask) override;
    bool FlushTo(LogWriter* writer, FlushToState& state,
                 const std::function<FilterResult(log_id_t log_id, pid_t pid, uint64_t sequence,
                                                  log_time realtime)>& filter) override;

    bool Clear(log_id_t id, uid_t uid) override;
    size_t GetSize(log_id_t id) override;
    bool SetSize(log_id_t id, size_t size) override;

    uint64_t sequence() const override { return sequence_.load(std::memory_order_relaxed); }

  private:
    bool ShouldLog(log_id_t log_id, const char* msg, uint16_t len);
    void MaybePrune(log_id_t log_id) REQUIRES(lock_);
    bool Prune(log_id_t log_id, size_t bytes_to_free, uid_t uid) REQUIRES(lock_);
    void KickReader(LogReaderThread* reader, log_id_t id, size_t bytes_to_free)
            REQUIRES_SHARED(lock_);
    void NotifyReadersOfPrune(log_id_t log_id, const std::list<SerializedLogChunk>::iterator& chunk)
            REQUIRES(reader_list_->reader_threads_lock());
    void RemoveChunkFromStats(log_id_t log_id, SerializedLogChunk& chunk);
    size_t GetSizeUsed(log_id_t id) REQUIRES(lock_);

    LogReaderList* reader_list_;
    LogTags* tags_;
    LogStatistics* stats_;

    size_t max_size_[LOG_ID_MAX] GUARDED_BY(lock_) = {};
    std::list<SerializedLogChunk> logs_[LOG_ID_MAX] GUARDED_BY(lock_);
    RwLock lock_;

    std::atomic<uint64_t> sequence_ = 1;
};
