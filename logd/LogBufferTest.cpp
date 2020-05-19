/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "LogBuffer.h"

#include <unistd.h>

#include <memory>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

#include "ChattyLogBuffer.h"
#include "LogReaderList.h"
#include "LogReaderThread.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogWhiteBlackList.h"
#include "LogWriter.h"

using android::base::Join;
using android::base::StringPrintf;

#ifndef __ANDROID__
unsigned long __android_logger_get_buffer_size(log_id_t) {
    return 1024 * 1024;
}

bool __android_logger_valid_buffer_size(unsigned long) {
    return true;
}
#endif

void android::prdebug(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}

char* android::uidToName(uid_t) {
    return nullptr;
}

class TestWriter : public LogWriter {
  public:
    TestWriter(std::vector<std::pair<logger_entry, std::string>>* msgs, bool* released)
        : LogWriter(0, true, true), msgs_(msgs), released_(released) {}
    bool Write(const logger_entry& entry, const char* message) override {
        msgs_->emplace_back(entry, std::string(message, entry.len));
        return true;
    }

    void Release() {
        if (released_) *released_ = true;
    }

    std::string name() const override { return "test_writer"; }

  private:
    std::vector<std::pair<logger_entry, std::string>>* msgs_;
    bool* released_;
};

class LogBufferTest : public testing::Test {
  protected:
    void SetUp() override {
        log_buffer_.reset(new ChattyLogBuffer(&reader_list_, &tags_, &prune_, &stats_));
    }

    void FixupMessages(std::vector<std::pair<logger_entry, std::string>>* messages) {
        for (auto& [entry, message] : *messages) {
            entry.hdr_size = sizeof(logger_entry);
            entry.len = message.size();
        }
    }

    void LogMessages(const std::vector<std::pair<logger_entry, std::string>>& messages) {
        for (auto& [entry, message] : messages) {
            log_buffer_->Log(static_cast<log_id_t>(entry.lid), log_time(entry.sec, entry.nsec),
                             entry.uid, entry.pid, entry.tid, message.c_str(), message.size());
        }
    }

    std::vector<std::string> CompareLoggerEntries(const logger_entry& expected,
                                                  const logger_entry& result) {
        std::vector<std::string> errors;
        if (expected.len != result.len) {
            errors.emplace_back(
                    StringPrintf("len: %" PRIu16 " vs %" PRIu16, expected.len, result.len));
        }
        if (expected.hdr_size != result.hdr_size) {
            errors.emplace_back(StringPrintf("hdr_size: %" PRIu16 " vs %" PRIu16, expected.hdr_size,
                                             result.hdr_size));
        }
        if (expected.pid != result.pid) {
            errors.emplace_back(
                    StringPrintf("pid: %" PRIi32 " vs %" PRIi32, expected.pid, result.pid));
        }
        if (expected.tid != result.tid) {
            errors.emplace_back(
                    StringPrintf("tid: %" PRIu32 " vs %" PRIu32, expected.tid, result.tid));
        }
        if (expected.sec != result.sec) {
            errors.emplace_back(
                    StringPrintf("sec: %" PRIu32 " vs %" PRIu32, expected.sec, result.sec));
        }
        if (expected.nsec != result.nsec) {
            errors.emplace_back(
                    StringPrintf("nsec: %" PRIu32 " vs %" PRIu32, expected.nsec, result.nsec));
        }
        if (expected.lid != result.lid) {
            errors.emplace_back(
                    StringPrintf("lid: %" PRIu32 " vs %" PRIu32, expected.lid, result.lid));
        }
        if (expected.uid != result.uid) {
            errors.emplace_back(
                    StringPrintf("uid: %" PRIu32 " vs %" PRIu32, expected.uid, result.uid));
        }
        return errors;
    }

    std::string CompareMessages(const std::string& expected, const std::string& result) {
        if (expected == result) {
            return {};
        }
        auto shorten_string = [](const std::string& in) {
            if (in.size() > 10) {
                return in.substr(0, 10) + "...";
            }
            return in;
        };

        size_t diff_index = 0;
        for (; diff_index < std::min(expected.size(), result.size()); ++diff_index) {
            if (expected[diff_index] != result[diff_index]) {
                break;
            }
        }

        if (diff_index < 10) {
            auto expected_short = shorten_string(expected);
            auto result_short = shorten_string(result);
            return StringPrintf("msg: %s vs %s", expected_short.c_str(), result_short.c_str());
        }

        auto expected_short = shorten_string(expected.substr(diff_index));
        auto result_short = shorten_string(result.substr(diff_index));
        return StringPrintf("msg: index %zu: %s vs %s", diff_index, expected_short.c_str(),
                            result_short.c_str());
    }

    void CompareLogMessages(const std::vector<std::pair<logger_entry, std::string>>& expected,
                            const std::vector<std::pair<logger_entry, std::string>>& result) {
        EXPECT_EQ(expected.size(), result.size());
        size_t end = std::min(expected.size(), result.size());
        size_t num_errors = 0;
        for (size_t i = 0; i < end; ++i) {
            auto errors = CompareLoggerEntries(expected[i].first, result[i].first);
            auto msg_error = CompareMessages(expected[i].second, result[i].second);
            if (!msg_error.empty()) {
                errors.emplace_back(msg_error);
            }
            if (!errors.empty()) {
                GTEST_LOG_(ERROR) << "Mismatch log message " << i << " " << Join(errors, " ");
                ++num_errors;
            }
        }
        EXPECT_EQ(0U, num_errors);
    }

    LogReaderList reader_list_;
    LogTags tags_;
    PruneList prune_;
    LogStatistics stats_{false};
    std::unique_ptr<LogBuffer> log_buffer_;
};

TEST_F(LogBufferTest, smoke) {
    std::vector<std::pair<logger_entry, std::string>> log_messages = {
            {{
                     .pid = 1,
                     .tid = 1,
                     .sec = 1234,
                     .nsec = 323001,
                     .lid = LOG_ID_MAIN,
                     .uid = 0,
             },
             "smoke test"},
    };
    FixupMessages(&log_messages);
    LogMessages(log_messages);

    std::vector<std::pair<logger_entry, std::string>> read_log_messages;
    std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, nullptr));
    uint64_t flush_result = log_buffer_->FlushTo(test_writer.get(), 1, nullptr, nullptr);
    EXPECT_EQ(1ULL, flush_result);
    CompareLogMessages(log_messages, read_log_messages);
}

TEST_F(LogBufferTest, smoke_with_reader_thread) {
    std::vector<std::pair<logger_entry, std::string>> log_messages = {
            {{.pid = 1, .tid = 2, .sec = 10000, .nsec = 20001, .lid = LOG_ID_MAIN, .uid = 0},
             "first"},
            {{.pid = 10, .tid = 2, .sec = 10000, .nsec = 20002, .lid = LOG_ID_MAIN, .uid = 0},
             "second"},
            {{.pid = 100, .tid = 2, .sec = 10000, .nsec = 20003, .lid = LOG_ID_KERNEL, .uid = 0},
             "third"},
            {{.pid = 10, .tid = 2, .sec = 10000, .nsec = 20004, .lid = LOG_ID_MAIN, .uid = 0},
             "fourth"},
            {{.pid = 1, .tid = 2, .sec = 10000, .nsec = 20005, .lid = LOG_ID_RADIO, .uid = 0},
             "fifth"},
            {{.pid = 2, .tid = 2, .sec = 10000, .nsec = 20006, .lid = LOG_ID_RADIO, .uid = 0},
             "sixth"},
            {{.pid = 3, .tid = 2, .sec = 10000, .nsec = 20007, .lid = LOG_ID_RADIO, .uid = 0},
             "seventh"},
            {{.pid = 4, .tid = 2, .sec = 10000, .nsec = 20008, .lid = LOG_ID_MAIN, .uid = 0},
             "eighth"},
            {{.pid = 5, .tid = 2, .sec = 10000, .nsec = 20009, .lid = LOG_ID_CRASH, .uid = 0},
             "nineth"},
            {{.pid = 6, .tid = 2, .sec = 10000, .nsec = 20011, .lid = LOG_ID_MAIN, .uid = 0},
             "tenth"},
    };
    FixupMessages(&log_messages);
    LogMessages(log_messages);

    std::vector<std::pair<logger_entry, std::string>> read_log_messages;
    bool released = false;

    {
        auto lock = std::unique_lock{reader_list_.reader_threads_lock()};
        std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, &released));
        std::unique_ptr<LogReaderThread> log_reader(
                new LogReaderThread(log_buffer_.get(), &reader_list_, std::move(test_writer), true,
                                    0, ~0, 0, {}, 1, {}));
        reader_list_.reader_threads().emplace_back(std::move(log_reader));
    }

    while (!released) {
        usleep(5000);
    }
    {
        auto lock = std::unique_lock{reader_list_.reader_threads_lock()};
        EXPECT_EQ(0U, reader_list_.reader_threads().size());
    }
    CompareLogMessages(log_messages, read_log_messages);
}

// Generate random messages, set the 'sec' parameter explicit though, to be able to track the
// expected order of messages.
std::pair<logger_entry, std::string> GenerateRandomLogMessage(uint32_t sec) {
    auto rand_uint32 = [](int max) -> uint32_t { return rand() % max; };
    logger_entry entry = {
            .hdr_size = sizeof(logger_entry),
            .pid = rand() % 5000,
            .tid = rand_uint32(5000),
            .sec = sec,
            .nsec = rand_uint32(NS_PER_SEC),
            .lid = rand_uint32(LOG_ID_STATS),
            .uid = rand_uint32(100000),
    };

    // See comment in ChattyLogBuffer::Log() for why this is disallowed.
    if (entry.nsec % 1000 == 0) {
        ++entry.nsec;
    }

    if (entry.lid == LOG_ID_EVENTS) {
        entry.lid = LOG_ID_KERNEL;
    }

    std::string message;
    char priority = ANDROID_LOG_INFO + rand() % 2;
    message.push_back(priority);

    int tag_length = 2 + rand() % 10;
    for (int i = 0; i < tag_length; ++i) {
        message.push_back('a' + rand() % 26);
    }
    message.push_back('\0');

    int msg_length = 2 + rand() % 1000;
    for (int i = 0; i < msg_length; ++i) {
        message.push_back('a' + rand() % 26);
    }
    message.push_back('\0');

    entry.len = message.size();

    return {entry, message};
}

TEST_F(LogBufferTest, random_messages) {
    srand(1);
    std::vector<std::pair<logger_entry, std::string>> log_messages;
    for (size_t i = 0; i < 1000; ++i) {
        log_messages.emplace_back(GenerateRandomLogMessage(i));
    }
    LogMessages(log_messages);

    std::vector<std::pair<logger_entry, std::string>> read_log_messages;
    bool released = false;

    {
        auto lock = std::unique_lock{reader_list_.reader_threads_lock()};
        std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, &released));
        std::unique_ptr<LogReaderThread> log_reader(
                new LogReaderThread(log_buffer_.get(), &reader_list_, std::move(test_writer), true,
                                    0, ~0, 0, {}, 1, {}));
        reader_list_.reader_threads().emplace_back(std::move(log_reader));
    }

    while (!released) {
        usleep(5000);
    }
    {
        auto lock = std::unique_lock{reader_list_.reader_threads_lock()};
        EXPECT_EQ(0U, reader_list_.reader_threads().size());
    }
    CompareLogMessages(log_messages, read_log_messages);
}
