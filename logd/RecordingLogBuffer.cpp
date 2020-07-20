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

#include "RecordingLogBuffer.h"

#include <android-base/file.h>

static void WriteLogMessage(int fd, const RecordedLogMessage& meta, const std::string& msg) {
    android::base::WriteFully(fd, &meta, sizeof(meta));
    android::base::WriteFully(fd, msg.c_str(), meta.msg_len);
}

void RecordingLogBuffer::RecordLogMessage(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid,
                                          pid_t tid, const char* msg, uint16_t len) {
    auto lock = std::lock_guard{lock_};
    if (len > LOGGER_ENTRY_MAX_PAYLOAD) {
        len = LOGGER_ENTRY_MAX_PAYLOAD;
    }

    RecordedLogMessage recorded_log_message = {
            .uid = uid,
            .pid = static_cast<uint32_t>(pid),
            .tid = static_cast<uint32_t>(tid),
            .realtime = realtime,
            .msg_len = len,
            .log_id = static_cast<uint8_t>(log_id),
    };

    if (!fd_.ok()) {
        fd_.reset(open("/data/misc/logd/recorded-messages",
                       O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666));
        if (!fd_.ok()) {
            since_boot_messages_.emplace_back(recorded_log_message, std::string(msg, len));
            return;
        } else {
            for (const auto& [meta, msg] : since_boot_messages_) {
                WriteLogMessage(fd_.get(), meta, msg);
            }
        }
    }

    WriteLogMessage(fd_.get(), recorded_log_message, std::string(msg, len));
}

int RecordingLogBuffer::Log(log_id_t log_id, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                            const char* msg, uint16_t len) {
    RecordLogMessage(log_id, realtime, uid, pid, tid, msg, len);
    return SimpleLogBuffer::Log(log_id, realtime, uid, pid, tid, msg, len);
}