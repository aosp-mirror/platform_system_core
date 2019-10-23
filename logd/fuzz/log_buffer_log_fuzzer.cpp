/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include "../LogBuffer.h"
#include "../LogTimes.h"

namespace android {
struct LogInput {
  public:
    log_id_t log_id;  // char
    log_time realtime;
    uid_t uid;
    pid_t pid;
    pid_t tid;
};

int write_log_messages(const uint8_t* data, size_t* data_left, LogBuffer* log_buffer) {
    const LogInput* logInput = reinterpret_cast<const LogInput*>(data);
    data += sizeof(LogInput);
    *data_left -= sizeof(LogInput);

    uint8_t tag_length = data[0] % 32;
    uint8_t msg_length = data[1] % 32;
    if (tag_length < 2 || msg_length < 2) {
        // Not enough data for tag and message
        return 0;
    }

    data += 2 * sizeof(uint8_t);
    *data_left -= 2 * sizeof(uint8_t);

    if (*data_left < tag_length + msg_length) {
        // Not enough data for tag and message
        return 0;
    }

    // We need nullterm'd strings
    char* msg = new char[tag_length + msg_length + 2];
    char* msg_only = msg + tag_length + 1;
    memcpy(msg, data, tag_length);
    msg[tag_length] = '\0';
    memcpy(msg_only, data, msg_length);
    msg_only[msg_length] = '\0';
    data += tag_length + msg_length;
    *data_left -= tag_length + msg_length;

    // Other elements not in enum.
    log_id_t log_id = static_cast<log_id_t>(unsigned(logInput->log_id) % (LOG_ID_MAX + 1));
    log_buffer->log(log_id, logInput->realtime, logInput->uid, logInput->pid, logInput->tid, msg,
                    tag_length + msg_length + 2);
    delete[] msg;
    return 1;
}

// Because system/core/logd/main.cpp redefines this.
void prdebug(char const* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // We want a random tag length and a random remaining message length
    if (data == nullptr || size < sizeof(LogInput) + 2 * sizeof(uint8_t)) {
        return 0;
    }

    LastLogTimes times;
    LogBuffer log_buffer(&times);
    size_t data_left = size;

    log_buffer.enableStatistics();
    // We want to get pruning code to get called.
    log_id_for_each(i) { log_buffer.setSize(i, 10000); }

    while (data_left >= sizeof(LogInput) + 2 * sizeof(uint8_t)) {
        if (!write_log_messages(data, &data_left, &log_buffer)) {
            return 0;
        }
    }

    log_id_for_each(i) { log_buffer.clear(i); }
    return 0;
}
}  // namespace android
