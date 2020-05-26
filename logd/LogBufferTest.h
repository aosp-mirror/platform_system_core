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

#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "ChattyLogBuffer.h"
#include "LogReaderList.h"
#include "LogStatistics.h"
#include "LogTags.h"
#include "LogWhiteBlackList.h"
#include "SimpleLogBuffer.h"

struct LogMessage {
    logger_entry entry;
    std::string message;
    bool regex_compare = false;  // Only set for expected messages, when true 'message' should be
                                 // interpretted as a regex.
};

// Compares the ordered list of expected and result, causing a test failure with appropriate
// information on failure.
void CompareLogMessages(const std::vector<LogMessage>& expected,
                        const std::vector<LogMessage>& result);
// Sets hdr_size and len parameters appropriately.
void FixupMessages(std::vector<LogMessage>* messages);

class TestWriter : public LogWriter {
  public:
    TestWriter(std::vector<LogMessage>* msgs, bool* released)
        : LogWriter(0, true, true), msgs_(msgs), released_(released) {}
    bool Write(const logger_entry& entry, const char* message) override {
        msgs_->emplace_back(LogMessage{entry, std::string(message, entry.len), false});
        return true;
    }

    void Release() {
        if (released_) *released_ = true;
    }

    std::string name() const override { return "test_writer"; }

  private:
    std::vector<LogMessage>* msgs_;
    bool* released_;
};

class LogBufferTest : public testing::TestWithParam<std::string> {
  protected:
    void SetUp() override {
        if (GetParam() == "chatty") {
            log_buffer_.reset(new ChattyLogBuffer(&reader_list_, &tags_, &prune_, &stats_));
        } else if (GetParam() == "simple") {
            log_buffer_.reset(new SimpleLogBuffer(&reader_list_, &tags_, &stats_));
        } else {
            FAIL() << "Unknown buffer type selected for test";
        }
    }

    void LogMessages(const std::vector<LogMessage>& messages) {
        for (auto& [entry, message, _] : messages) {
            log_buffer_->Log(static_cast<log_id_t>(entry.lid), log_time(entry.sec, entry.nsec),
                             entry.uid, entry.pid, entry.tid, message.c_str(), message.size());
        }
    }

    LogReaderList reader_list_;
    LogTags tags_;
    PruneList prune_;
    LogStatistics stats_{false};
    std::unique_ptr<LogBuffer> log_buffer_;
};
