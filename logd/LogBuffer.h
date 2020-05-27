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

#include <log/log.h>
#include <sysutils/SocketClient.h>

#include "LogBufferElement.h"

class LogWriter;

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
    // lastTid is an optional context to help detect if the last previous
    // valid message was from the same source so we can differentiate chatty
    // filter types (identical or expired)
    static const uint64_t FLUSH_ERROR = 0;
    virtual uint64_t FlushTo(
            LogWriter* writer, uint64_t start,
            pid_t* last_tid,  // nullable
            const std::function<FilterResult(const LogBufferElement* element)>& filter) = 0;

    virtual bool Clear(log_id_t id, uid_t uid) = 0;
    virtual unsigned long GetSize(log_id_t id) = 0;
    virtual int SetSize(log_id_t id, unsigned long size) = 0;

    virtual uint64_t sequence() const = 0;
};