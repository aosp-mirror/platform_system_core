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

#include "LogBufferTest.h"

#include <unistd.h>

#include <limits>
#include <memory>
#include <regex>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "LogReaderThread.h"
#include "LogWriter.h"

using android::base::Join;
using android::base::Split;
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

static std::vector<std::string> CompareLoggerEntries(const logger_entry& expected,
                                                     const logger_entry& result, bool ignore_len) {
    std::vector<std::string> errors;
    if (!ignore_len && expected.len != result.len) {
        errors.emplace_back(
                StringPrintf("len: expected %" PRIu16 " vs %" PRIu16, expected.len, result.len));
    }
    if (expected.hdr_size != result.hdr_size) {
        errors.emplace_back(StringPrintf("hdr_size: %" PRIu16 " vs %" PRIu16, expected.hdr_size,
                                         result.hdr_size));
    }
    if (expected.pid != result.pid) {
        errors.emplace_back(
                StringPrintf("pid: expected %" PRIi32 " vs %" PRIi32, expected.pid, result.pid));
    }
    if (expected.tid != result.tid) {
        errors.emplace_back(
                StringPrintf("tid: expected %" PRIu32 " vs %" PRIu32, expected.tid, result.tid));
    }
    if (expected.sec != result.sec) {
        errors.emplace_back(
                StringPrintf("sec: expected %" PRIu32 " vs %" PRIu32, expected.sec, result.sec));
    }
    if (expected.nsec != result.nsec) {
        errors.emplace_back(
                StringPrintf("nsec: expected %" PRIu32 " vs %" PRIu32, expected.nsec, result.nsec));
    }
    if (expected.lid != result.lid) {
        errors.emplace_back(
                StringPrintf("lid: expected %" PRIu32 " vs %" PRIu32, expected.lid, result.lid));
    }
    if (expected.uid != result.uid) {
        errors.emplace_back(
                StringPrintf("uid: expected %" PRIu32 " vs %" PRIu32, expected.uid, result.uid));
    }
    return errors;
}

static std::string MakePrintable(std::string in) {
    if (in.size() > 80) {
        in = in.substr(0, 80) + "...";
    }
    std::string result;
    for (const char c : in) {
        if (isprint(c)) {
            result.push_back(c);
        } else {
            result.append(StringPrintf("\\%02x", static_cast<int>(c) & 0xFF));
        }
    }
    return result;
}

static std::string CompareMessages(const std::string& expected, const std::string& result) {
    if (expected == result) {
        return {};
    }
    size_t diff_index = 0;
    for (; diff_index < std::min(expected.size(), result.size()); ++diff_index) {
        if (expected[diff_index] != result[diff_index]) {
            break;
        }
    }

    if (diff_index < 10) {
        auto expected_short = MakePrintable(expected);
        auto result_short = MakePrintable(result);
        return StringPrintf("msg: expected '%s' vs '%s'", expected_short.c_str(),
                            result_short.c_str());
    }

    auto expected_short = MakePrintable(expected.substr(diff_index));
    auto result_short = MakePrintable(result.substr(diff_index));
    return StringPrintf("msg: index %zu: expected '%s' vs '%s'", diff_index, expected_short.c_str(),
                        result_short.c_str());
}

static std::string CompareRegexMessages(const std::string& expected, const std::string& result) {
    auto expected_pieces = Split(expected, std::string("\0", 1));
    auto result_pieces = Split(result, std::string("\0", 1));

    if (expected_pieces.size() != 3 || result_pieces.size() != 3) {
        return StringPrintf(
                "msg: should have 3 null delimited strings found %d in expected, %d in result: "
                "'%s' vs '%s'",
                static_cast<int>(expected_pieces.size()), static_cast<int>(result_pieces.size()),
                MakePrintable(expected).c_str(), MakePrintable(result).c_str());
    }
    if (expected_pieces[0] != result_pieces[0]) {
        return StringPrintf("msg: tag/priority mismatch expected '%s' vs '%s'",
                            MakePrintable(expected_pieces[0]).c_str(),
                            MakePrintable(result_pieces[0]).c_str());
    }
    std::regex expected_tag_regex(expected_pieces[1]);
    if (!std::regex_search(result_pieces[1], expected_tag_regex)) {
        return StringPrintf("msg: message regex mismatch expected '%s' vs '%s'",
                            MakePrintable(expected_pieces[1]).c_str(),
                            MakePrintable(result_pieces[1]).c_str());
    }
    if (expected_pieces[2] != result_pieces[2]) {
        return StringPrintf("msg: nothing expected after final null character '%s' vs '%s'",
                            MakePrintable(expected_pieces[2]).c_str(),
                            MakePrintable(result_pieces[2]).c_str());
    }
    return {};
}

void CompareLogMessages(const std::vector<LogMessage>& expected,
                        const std::vector<LogMessage>& result) {
    EXPECT_EQ(expected.size(), result.size());
    size_t end = std::min(expected.size(), result.size());
    size_t num_errors = 0;
    for (size_t i = 0; i < end; ++i) {
        auto errors =
                CompareLoggerEntries(expected[i].entry, result[i].entry, expected[i].regex_compare);
        auto msg_error = expected[i].regex_compare
                                 ? CompareRegexMessages(expected[i].message, result[i].message)
                                 : CompareMessages(expected[i].message, result[i].message);
        if (!msg_error.empty()) {
            errors.emplace_back(msg_error);
        }
        if (!errors.empty()) {
            GTEST_LOG_(ERROR) << "Mismatch log message " << i << "\n" << Join(errors, "\n");
            ++num_errors;
        }
    }
    EXPECT_EQ(0U, num_errors);
}

void FixupMessages(std::vector<LogMessage>* messages) {
    for (auto& [entry, message, _] : *messages) {
        entry.hdr_size = sizeof(logger_entry);
        entry.len = message.size();
    }
}

TEST_P(LogBufferTest, smoke) {
    std::vector<LogMessage> log_messages = {
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

    std::vector<LogMessage> read_log_messages;
    std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, nullptr));
    uint64_t flush_result = log_buffer_->FlushTo(test_writer.get(), 1, nullptr, nullptr);
    EXPECT_EQ(1ULL, flush_result);
    CompareLogMessages(log_messages, read_log_messages);
}

TEST_P(LogBufferTest, smoke_with_reader_thread) {
    std::vector<LogMessage> log_messages = {
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

    std::vector<LogMessage> read_log_messages;
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
LogMessage GenerateRandomLogMessage(uint32_t sec) {
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

TEST_P(LogBufferTest, random_messages) {
    srand(1);
    std::vector<LogMessage> log_messages;
    for (size_t i = 0; i < 1000; ++i) {
        log_messages.emplace_back(GenerateRandomLogMessage(i));
    }
    LogMessages(log_messages);

    std::vector<LogMessage> read_log_messages;
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

INSTANTIATE_TEST_CASE_P(LogBufferTests, LogBufferTest, testing::Values("chatty", "simple"));
