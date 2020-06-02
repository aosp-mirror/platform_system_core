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

class ChattyLogBufferTest : public LogBufferTest {};

TEST_P(ChattyLogBufferTest, deduplication_simple) {
    auto make_message = [&](uint32_t sec, const char* tag, const char* msg,
                            bool regex = false) -> LogMessage {
        logger_entry entry = {
                .pid = 1, .tid = 1, .sec = sec, .nsec = 1, .lid = LOG_ID_MAIN, .uid = 0};
        std::string message;
        message.push_back(ANDROID_LOG_INFO);
        message.append(tag);
        message.push_back('\0');
        message.append(msg);
        message.push_back('\0');
        return {entry, message, regex};
    };

    // clang-format off
    std::vector<LogMessage> log_messages = {
            make_message(0, "test_tag", "duplicate"),
            make_message(1, "test_tag", "duplicate"),
            make_message(2, "test_tag", "not_same"),
            make_message(3, "test_tag", "duplicate"),
            make_message(4, "test_tag", "duplicate"),
            make_message(5, "test_tag", "not_same"),
            make_message(6, "test_tag", "duplicate"),
            make_message(7, "test_tag", "duplicate"),
            make_message(8, "test_tag", "duplicate"),
            make_message(9, "test_tag", "not_same"),
            make_message(10, "test_tag", "duplicate"),
            make_message(11, "test_tag", "duplicate"),
            make_message(12, "test_tag", "duplicate"),
            make_message(13, "test_tag", "duplicate"),
            make_message(14, "test_tag", "duplicate"),
            make_message(15, "test_tag", "duplicate"),
            make_message(16, "test_tag", "not_same"),
            make_message(100, "test_tag", "duplicate"),
            make_message(200, "test_tag", "duplicate"),
            make_message(300, "test_tag", "duplicate"),
    };
    // clang-format on
    FixupMessages(&log_messages);
    LogMessages(log_messages);

    std::vector<LogMessage> read_log_messages;
    std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, nullptr));
    std::unique_ptr<FlushToState> flush_to_state = log_buffer_->CreateFlushToState(1, kLogMaskAll);
    EXPECT_TRUE(log_buffer_->FlushTo(test_writer.get(), *flush_to_state, nullptr));

    std::vector<LogMessage> expected_log_messages = {
            make_message(0, "test_tag", "duplicate"),
            make_message(1, "test_tag", "duplicate"),
            make_message(2, "test_tag", "not_same"),
            make_message(3, "test_tag", "duplicate"),
            make_message(4, "test_tag", "duplicate"),
            make_message(5, "test_tag", "not_same"),
            // 3 duplicate logs together print the first, a 1 count chatty message, then the last.
            make_message(6, "test_tag", "duplicate"),
            make_message(7, "chatty", "uid=0\\([^\\)]+\\) [^ ]+ identical 1 line", true),
            make_message(8, "test_tag", "duplicate"),
            make_message(9, "test_tag", "not_same"),
            // 6 duplicate logs together print the first, a 4 count chatty message, then the last.
            make_message(10, "test_tag", "duplicate"),
            make_message(14, "chatty", "uid=0\\([^\\)]+\\) [^ ]+ identical 4 lines", true),
            make_message(15, "test_tag", "duplicate"),
            make_message(16, "test_tag", "not_same"),
            // duplicate logs > 1 minute apart are not deduplicated.
            make_message(100, "test_tag", "duplicate"),
            make_message(200, "test_tag", "duplicate"),
            make_message(300, "test_tag", "duplicate"),
    };
    FixupMessages(&expected_log_messages);
    CompareLogMessages(expected_log_messages, read_log_messages);
};

TEST_P(ChattyLogBufferTest, deduplication_overflow) {
    auto make_message = [&](uint32_t sec, const char* tag, const char* msg,
                            bool regex = false) -> LogMessage {
        logger_entry entry = {
                .pid = 1, .tid = 1, .sec = sec, .nsec = 1, .lid = LOG_ID_MAIN, .uid = 0};
        std::string message;
        message.push_back(ANDROID_LOG_INFO);
        message.append(tag);
        message.push_back('\0');
        message.append(msg);
        message.push_back('\0');
        return {entry, message, regex};
    };

    uint32_t sec = 0;
    std::vector<LogMessage> log_messages = {
            make_message(sec++, "test_tag", "normal"),
    };
    size_t expired_per_chatty_message = std::numeric_limits<uint16_t>::max();
    for (size_t i = 0; i < expired_per_chatty_message + 3; ++i) {
        log_messages.emplace_back(make_message(sec++, "test_tag", "duplicate"));
    }
    log_messages.emplace_back(make_message(sec++, "test_tag", "normal"));
    FixupMessages(&log_messages);
    LogMessages(log_messages);

    std::vector<LogMessage> read_log_messages;
    std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, nullptr));
    std::unique_ptr<FlushToState> flush_to_state = log_buffer_->CreateFlushToState(1, kLogMaskAll);
    EXPECT_TRUE(log_buffer_->FlushTo(test_writer.get(), *flush_to_state, nullptr));

    std::vector<LogMessage> expected_log_messages = {
            make_message(0, "test_tag", "normal"),
            make_message(1, "test_tag", "duplicate"),
            make_message(expired_per_chatty_message + 1, "chatty",
                         "uid=0\\([^\\)]+\\) [^ ]+ identical 65535 lines", true),
            make_message(expired_per_chatty_message + 2, "chatty",
                         "uid=0\\([^\\)]+\\) [^ ]+ identical 1 line", true),
            make_message(expired_per_chatty_message + 3, "test_tag", "duplicate"),
            make_message(expired_per_chatty_message + 4, "test_tag", "normal"),
    };
    FixupMessages(&expected_log_messages);
    CompareLogMessages(expected_log_messages, read_log_messages);
}

TEST_P(ChattyLogBufferTest, deduplication_liblog) {
    auto make_message = [&](uint32_t sec, int32_t tag, int32_t count) -> LogMessage {
        logger_entry entry = {
                .pid = 1, .tid = 1, .sec = sec, .nsec = 1, .lid = LOG_ID_EVENTS, .uid = 0};
        android_log_event_int_t liblog_event = {
                .header.tag = tag, .payload.type = EVENT_TYPE_INT, .payload.data = count};
        return {entry, std::string(reinterpret_cast<char*>(&liblog_event), sizeof(liblog_event)),
                false};
    };

    // LIBLOG_LOG_TAG
    std::vector<LogMessage> log_messages = {
            make_message(0, 1234, 1),
            make_message(1, LIBLOG_LOG_TAG, 3),
            make_message(2, 1234, 2),
            make_message(3, LIBLOG_LOG_TAG, 3),
            make_message(4, LIBLOG_LOG_TAG, 4),
            make_message(5, 1234, 223),
            make_message(6, LIBLOG_LOG_TAG, 2),
            make_message(7, LIBLOG_LOG_TAG, 3),
            make_message(8, LIBLOG_LOG_TAG, 4),
            make_message(9, 1234, 227),
            make_message(10, LIBLOG_LOG_TAG, 1),
            make_message(11, LIBLOG_LOG_TAG, 3),
            make_message(12, LIBLOG_LOG_TAG, 2),
            make_message(13, LIBLOG_LOG_TAG, 3),
            make_message(14, LIBLOG_LOG_TAG, 5),
            make_message(15, 1234, 227),
            make_message(16, LIBLOG_LOG_TAG, 2),
            make_message(17, LIBLOG_LOG_TAG, std::numeric_limits<int32_t>::max()),
            make_message(18, LIBLOG_LOG_TAG, 3),
            make_message(19, LIBLOG_LOG_TAG, 5),
            make_message(20, 1234, 227),
    };
    FixupMessages(&log_messages);
    LogMessages(log_messages);

    std::vector<LogMessage> read_log_messages;
    std::unique_ptr<LogWriter> test_writer(new TestWriter(&read_log_messages, nullptr));
    std::unique_ptr<FlushToState> flush_to_state = log_buffer_->CreateFlushToState(1, kLogMaskAll);
    EXPECT_TRUE(log_buffer_->FlushTo(test_writer.get(), *flush_to_state, nullptr));

    std::vector<LogMessage> expected_log_messages = {
            make_message(0, 1234, 1),
            make_message(1, LIBLOG_LOG_TAG, 3),
            make_message(2, 1234, 2),
            make_message(3, LIBLOG_LOG_TAG, 3),
            make_message(4, LIBLOG_LOG_TAG, 4),
            make_message(5, 1234, 223),
            // More than 2 liblog events (3 here), sum their value into the third message.
            make_message(6, LIBLOG_LOG_TAG, 2),
            make_message(8, LIBLOG_LOG_TAG, 7),
            make_message(9, 1234, 227),
            // More than 2 liblog events (5 here), sum their value into the third message.
            make_message(10, LIBLOG_LOG_TAG, 1),
            make_message(14, LIBLOG_LOG_TAG, 13),
            make_message(15, 1234, 227),
            // int32_t max is the max for a chatty message, beyond that we must use new messages.
            make_message(16, LIBLOG_LOG_TAG, 2),
            make_message(17, LIBLOG_LOG_TAG, std::numeric_limits<int32_t>::max()),
            make_message(19, LIBLOG_LOG_TAG, 8),
            make_message(20, 1234, 227),
    };
    FixupMessages(&expected_log_messages);
    CompareLogMessages(expected_log_messages, read_log_messages);
};

INSTANTIATE_TEST_CASE_P(ChattyLogBufferTests, ChattyLogBufferTest, testing::Values("chatty"));
