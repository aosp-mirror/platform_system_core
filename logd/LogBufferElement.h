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

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <log/log.h>

#include "LogWriter.h"

class LogStatistics;

#define EXPIRE_HOUR_THRESHOLD 24  // Only expire chatty UID logs to preserve
                                  // non-chatty UIDs less than this age in hours
#define EXPIRE_THRESHOLD 10       // A smaller expire count is considered too
                                  // chatty for the temporal expire messages
#define EXPIRE_RATELIMIT 10  // maximum rate in seconds to report expiration

class __attribute__((packed)) LogBufferElement {
  public:
    LogBufferElement(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                     uint64_t sequence, const char* msg, uint16_t len);
    LogBufferElement(const LogBufferElement& elem);
    LogBufferElement(LogBufferElement&& elem);
    ~LogBufferElement();

    bool IsBinary() const { return (log_id_ == LOG_ID_EVENTS) || (log_id_ == LOG_ID_SECURITY); }

    uint32_t GetTag() const;
    uint16_t SetDropped(uint16_t value);

    bool FlushTo(LogWriter* writer, LogStatistics* parent, bool lastSame);

    log_id_t log_id() const { return static_cast<log_id_t>(log_id_); }
    uid_t uid() const { return uid_; }
    pid_t pid() const { return pid_; }
    pid_t tid() const { return tid_; }
    uint16_t msg_len() const { return dropped_ ? 0 : msg_len_; }
    const char* msg() const { return dropped_ ? nullptr : msg_; }
    uint64_t sequence() const { return sequence_; }
    log_time realtime() const { return realtime_; }
    uint16_t dropped_count() const { return dropped_ ? dropped_count_ : 0; }

  private:
    // assumption: mDropped == true
    size_t PopulateDroppedMessage(char*& buffer, LogStatistics* parent, bool lastSame);

    // sized to match reality of incoming log packets
    const uint32_t uid_;
    const uint32_t pid_;
    const uint32_t tid_;
    uint64_t sequence_;
    log_time realtime_;
    union {
        char* msg_;    // mDropped == false
        int32_t tag_;  // mDropped == true
    };
    union {
        const uint16_t msg_len_;  // mDropped == false
        uint16_t dropped_count_;  // mDropped == true
    };
    const uint8_t log_id_;
    bool dropped_;
};
