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

#include "SimpleLogBuffer.h"

#include <string>
#include <tuple>
#include <vector>

#include <android-base/unique_fd.h>

#include "RecordedLogMessage.h"

class RecordingLogBuffer : public SimpleLogBuffer {
  public:
    RecordingLogBuffer(LogReaderList* reader_list, LogTags* tags, LogStatistics* stats)
        : SimpleLogBuffer(reader_list, tags, stats) {}

    int Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid, const char* msg,
            uint16_t len) override;

  private:
    void RecordLogMessage(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                          const char* msg, uint16_t len);

    std::vector<std::pair<RecordedLogMessage, std::string>> since_boot_messages_;
    android::base::unique_fd fd_;
};
