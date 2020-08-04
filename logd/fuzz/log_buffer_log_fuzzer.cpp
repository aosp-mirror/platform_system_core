/*
 * Copyright 2019 The Android Open Source Project
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
#include <string>

#include <android-base/logging.h>

#include "../ChattyLogBuffer.h"
#include "../LogReaderList.h"
#include "../LogReaderThread.h"
#include "../LogStatistics.h"
#include "../SerializedLogBuffer.h"

// We don't want to waste a lot of entropy on messages
#define MAX_MSG_LENGTH 5

// Tag IDs usually start at 1000, we only want to try 1000 through 1009
#define MIN_TAG_ID 1000
#define TAG_MOD 10

char* android::uidToName(uid_t) {
    return strdup("fake");
}

struct LogInput {
  public:
    log_id_t log_id;
    log_time realtime;
    uid_t uid;
    pid_t pid;
    pid_t tid;
    unsigned int log_mask;
};

int write_log_messages(const uint8_t** pdata, size_t* data_left, LogBuffer* log_buffer,
                       LogStatistics* stats) {
    const uint8_t* data = *pdata;
    const LogInput* logInput = reinterpret_cast<const LogInput*>(data);
    data += sizeof(LogInput);
    *data_left -= sizeof(LogInput);

    uint32_t tag = MIN_TAG_ID + data[0] % TAG_MOD;
    uint8_t msg_length = data[1] % MAX_MSG_LENGTH;
    if (msg_length < 2) {
        // Not enough data for message
        return 0;
    }

    data += 2 * sizeof(uint8_t);
    *data_left -= 2 * sizeof(uint8_t);

    if (*data_left < msg_length) {
        // Not enough data for tag and message
        *pdata = data;
        return 0;
    }

    // We need nullterm'd strings
    char msg[sizeof(uint32_t) + MAX_MSG_LENGTH + sizeof(char)];
    char* msg_only = msg + sizeof(uint32_t);
    memcpy(msg, &tag, sizeof(uint32_t));
    memcpy(msg_only, data, msg_length);
    msg_only[msg_length] = '\0';
    data += msg_length;
    *data_left -= msg_length;

    // Other elements not in enum.
    log_id_t log_id = static_cast<log_id_t>(unsigned(logInput->log_id) % (LOG_ID_MAX + 1));
    log_buffer->Log(log_id, logInput->realtime, logInput->uid, logInput->pid, logInput->tid, msg,
                    sizeof(uint32_t) + msg_length + 1);
    stats->Format(logInput->uid, logInput->pid, logInput->log_mask);
    *pdata = data;
    return 1;
}

class NoopWriter : public LogWriter {
  public:
    NoopWriter() : LogWriter(0, true) {}
    bool Write(const logger_entry&, const char*) override { return true; }

    std::string name() const override { return "noop_writer"; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // We want a random tag length and a random remaining message length
    if (data == nullptr || size < sizeof(LogInput) + 2 * sizeof(uint8_t)) {
        return 0;
    }

    android::base::SetMinimumLogSeverity(android::base::ERROR);

    LogReaderList reader_list;
    LogTags tags;
    PruneList prune_list;
    LogStatistics stats(true, true);
    std::unique_ptr<LogBuffer> log_buffer;
#ifdef FUZZ_SERIALIZED
    log_buffer.reset(new SerializedLogBuffer(&reader_list, &tags, &stats));
#else
    log_buffer.reset(new ChattyLogBuffer(&reader_list, &tags, &prune_list, &stats));
#endif
    size_t data_left = size;
    const uint8_t** pdata = &data;

    prune_list.Init(nullptr);
    // We want to get pruning code to get called.
    log_id_for_each(i) { log_buffer->SetSize(i, 10000); }

    while (data_left >= sizeof(LogInput) + 2 * sizeof(uint8_t)) {
        if (!write_log_messages(pdata, &data_left, log_buffer.get(), &stats)) {
            return 0;
        }
    }

    // Read out all of the logs.
    {
        auto lock = std::unique_lock{reader_list.reader_threads_lock()};
        std::unique_ptr<LogWriter> test_writer(new NoopWriter());
        std::unique_ptr<LogReaderThread> log_reader(
                new LogReaderThread(log_buffer.get(), &reader_list, std::move(test_writer), true, 0,
                                    kLogMaskAll, 0, {}, 1, {}));
        reader_list.reader_threads().emplace_back(std::move(log_reader));
    }

    // Wait until the reader has finished.
    while (true) {
        usleep(50);
        auto lock = std::unique_lock{reader_list.reader_threads_lock()};
        if (reader_list.reader_threads().size() == 0) {
            break;
        }
    }

    log_id_for_each(i) { log_buffer->Clear(i, 0); }
    return 0;
}
