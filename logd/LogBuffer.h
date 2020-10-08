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

#include <sys/types.h>

#include <functional>
#include <memory>

#include <android-base/thread_annotations.h>
#include <log/log.h>
#include <log/log_read.h>

#include "LogWriter.h"
#include "LogdLock.h"

// A mask to represent which log buffers a reader is watching, values are (1 << LOG_ID_MAIN), etc.
using LogMask = uint32_t;
constexpr uint32_t kLogMaskAll = 0xFFFFFFFF;

// State that a LogBuffer may want to persist across calls to FlushTo().
class FlushToState {
  public:
    FlushToState(uint64_t start, LogMask log_mask) : start_(start), log_mask_(log_mask) {}
    virtual ~FlushToState() {}

    uint64_t start() const { return start_; }
    void set_start(uint64_t start) { start_ = start; }

    LogMask log_mask() const { return log_mask_; }

  private:
    uint64_t start_;
    LogMask log_mask_;
};

// Enum for the return values of the `filter` function passed to FlushTo().
enum class FilterResult {
    kSkip,
    kStop,
    kWrite,
};

class LogBuffer {
  public:
    virtual ~LogBuffer() {}

    virtual void Init() = 0;

    virtual int Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                    const char* msg, uint16_t len) = 0;

    virtual std::unique_ptr<FlushToState> CreateFlushToState(uint64_t start, LogMask log_mask)
            REQUIRES(logd_lock) = 0;
    virtual bool FlushTo(
            LogWriter* writer, FlushToState& state,
            const std::function<FilterResult(log_id_t log_id, pid_t pid, uint64_t sequence,
                                             log_time realtime)>& filter) REQUIRES(logd_lock) = 0;

    virtual bool Clear(log_id_t id, uid_t uid) = 0;
    virtual size_t GetSize(log_id_t id) = 0;
    virtual bool SetSize(log_id_t id, size_t size) = 0;

    virtual uint64_t sequence() const = 0;
};
