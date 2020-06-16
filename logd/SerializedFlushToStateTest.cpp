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

#include "SerializedFlushToState.h"

#include <map>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <gtest/gtest.h>

using android::base::Join;
using android::base::StringPrintf;

constexpr size_t kChunkSize = 3 * 4096;

class SerializedFlushToStateTest : public testing::Test {
  protected:
    void SetUp() override {
        // This test spams many unneeded INFO logs, so we suppress them.
        old_log_severity_ = android::base::SetMinimumLogSeverity(android::base::WARNING);
    }
    void TearDown() override { android::base::SetMinimumLogSeverity(old_log_severity_); }

    std::string TestReport(const std::vector<uint64_t>& expected,
                           const std::vector<uint64_t>& read) {
        auto sequence_to_log_id = [&](uint64_t sequence) -> int {
            for (const auto& [log_id, sequences] : sequence_numbers_per_buffer_) {
                if (std::find(sequences.begin(), sequences.end(), sequence) != sequences.end()) {
                    return log_id;
                }
            }
            return -1;
        };

        std::map<int, std::vector<uint64_t>> missing_sequences;
        std::vector<uint64_t> missing_expected;
        std::set_difference(expected.begin(), expected.end(), read.begin(), read.end(),
                            std::back_inserter(missing_expected));
        for (uint64_t sequence : missing_expected) {
            int log_id = sequence_to_log_id(sequence);
            missing_sequences[log_id].emplace_back(sequence);
        }

        std::map<int, std::vector<uint64_t>> extra_sequences;
        std::vector<uint64_t> extra_read;
        std::set_difference(read.begin(), read.end(), expected.begin(), expected.end(),
                            std::back_inserter(extra_read));
        for (uint64_t sequence : extra_read) {
            int log_id = sequence_to_log_id(sequence);
            extra_sequences[log_id].emplace_back(sequence);
        }

        std::vector<std::string> errors;
        for (const auto& [log_id, sequences] : missing_sequences) {
            errors.emplace_back(
                    StringPrintf("Log id %d missing %zu sequences", log_id, sequences.size()));
        }

        for (const auto& [log_id, sequences] : extra_sequences) {
            errors.emplace_back(
                    StringPrintf("Log id %d has extra %zu sequences", log_id, sequences.size()));
        }

        return Join(errors, ", ");
    }

    // Read sequence numbers in order from SerializedFlushToState for every mask combination and all
    // sequence numbers from 0 through the highest logged sequence number + 1.
    // This assumes that all of the logs have already been written.
    void TestAllReading() {
        uint64_t max_sequence = sequence_ + 1;
        uint32_t max_mask = (1 << LOG_ID_MAX) - 1;
        for (uint64_t sequence = 0; sequence < max_sequence; ++sequence) {
            for (uint32_t mask = 0; mask < max_mask; ++mask) {
                auto state = SerializedFlushToState{sequence, mask};
                state.InitializeLogs(log_chunks_);
                state.CheckForNewLogs();
                TestReading(sequence, mask, state);
            }
        }
    }

    // Similar to TestAllReading() except that it doesn't assume any logs are in the buffer, instead
    // it calls write_logs() in a loop for sequence/mask combination.  It clears log_chunks_ and
    // sequence_numbers_per_buffer_ between calls, such that only the sequence numbers written in
    // the previous call to write_logs() are expected.
    void TestAllReadingWithFutureMessages(const std::function<bool(int)>& write_logs) {
        uint64_t max_sequence = sequence_ + 1;
        uint32_t max_mask = (1 << LOG_ID_MAX) - 1;
        for (uint64_t sequence = 1; sequence < max_sequence; ++sequence) {
            for (uint32_t mask = 1; mask < max_mask; ++mask) {
                log_id_for_each(i) { log_chunks_[i].clear(); }
                auto state = SerializedFlushToState{sequence, mask};
                state.InitializeLogs(log_chunks_);
                int loop_count = 0;
                while (write_logs(loop_count++)) {
                    state.CheckForNewLogs();
                    TestReading(sequence, mask, state);
                    sequence_numbers_per_buffer_.clear();
                }
            }
        }
    }

    void TestReading(uint64_t start, LogMask log_mask, SerializedFlushToState& state) {
        std::vector<uint64_t> expected_sequence;
        log_id_for_each(i) {
            if (((1 << i) & log_mask) == 0) {
                continue;
            }
            for (const auto& sequence : sequence_numbers_per_buffer_[i]) {
                if (sequence >= start) {
                    expected_sequence.emplace_back(sequence);
                }
            }
        }
        std::sort(expected_sequence.begin(), expected_sequence.end());

        std::vector<uint64_t> read_sequence;

        while (state.HasUnreadLogs()) {
            auto top = state.PopNextUnreadLog();
            read_sequence.emplace_back(top.entry->sequence());
        }

        EXPECT_TRUE(std::is_sorted(read_sequence.begin(), read_sequence.end()));

        EXPECT_EQ(expected_sequence.size(), read_sequence.size());

        EXPECT_EQ(expected_sequence, read_sequence)
                << "start: " << start << " log_mask: " << log_mask << " "
                << TestReport(expected_sequence, read_sequence);
    }

    // Add a chunk with the given messages to the a given log buffer.  Keep track of the sequence
    // numbers for future validation.  Optionally mark the block as having finished writing.
    void AddChunkWithMessages(int buffer, bool finish_writing,
                              const std::vector<std::string>& messages) {
        auto chunk = SerializedLogChunk{kChunkSize};
        for (const auto& message : messages) {
            auto sequence = sequence_++;
            sequence_numbers_per_buffer_[buffer].emplace_back(sequence);
            ASSERT_TRUE(chunk.CanLog(message.size() + 1));
            chunk.Log(sequence, log_time(), 0, 1, 1, message.c_str(), message.size() + 1);
        }
        if (finish_writing) {
            chunk.FinishWriting();
        }
        log_chunks_[buffer].emplace_back(std::move(chunk));
    }

    android::base::LogSeverity old_log_severity_;
    std::map<int, std::vector<uint64_t>> sequence_numbers_per_buffer_;
    std::list<SerializedLogChunk> log_chunks_[LOG_ID_MAX];
    uint64_t sequence_ = 1;
};

// 0: multiple chunks, with variable number of entries, with/without finishing writing
// 1: 1 chunk with 1 log and finished writing
// 2: 1 chunk with 1 log and not finished writing
// 3: 1 chunk with 0 logs and not finished writing
// 4: 1 chunk with 0 logs and finished writing (impossible, but SerializedFlushToState handles it)
// 5-7: 0 chunks
TEST_F(SerializedFlushToStateTest, smoke) {
    AddChunkWithMessages(true, 0, {"1st", "2nd"});
    AddChunkWithMessages(true, 1, {"3rd"});
    AddChunkWithMessages(false, 0, {"4th"});
    AddChunkWithMessages(true, 0, {"4th", "5th", "more", "even", "more", "go", "here"});
    AddChunkWithMessages(false, 2, {"6th"});
    AddChunkWithMessages(true, 0, {"7th"});
    AddChunkWithMessages(false, 3, {});
    AddChunkWithMessages(true, 4, {});

    TestAllReading();
}

TEST_F(SerializedFlushToStateTest, random) {
    srand(1);
    for (int count = 0; count < 20; ++count) {
        unsigned int num_messages = 1 + rand() % 15;
        auto messages = std::vector<std::string>{num_messages, "same message"};

        bool compress = rand() % 2;
        int buf = rand() % LOG_ID_MAX;

        AddChunkWithMessages(compress, buf, messages);
    }

    TestAllReading();
}

// Same start as smoke, but we selectively write logs to the buffers and ensure they're read.
TEST_F(SerializedFlushToStateTest, future_writes) {
    auto write_logs = [&](int loop_count) {
        switch (loop_count) {
            case 0:
                // Initial writes.
                AddChunkWithMessages(true, 0, {"1st", "2nd"});
                AddChunkWithMessages(true, 1, {"3rd"});
                AddChunkWithMessages(false, 0, {"4th"});
                AddChunkWithMessages(true, 0, {"4th", "5th", "more", "even", "more", "go", "here"});
                AddChunkWithMessages(false, 2, {"6th"});
                AddChunkWithMessages(true, 0, {"7th"});
                AddChunkWithMessages(false, 3, {});
                AddChunkWithMessages(true, 4, {});
                break;
            case 1:
                // Smoke test, add a simple chunk.
                AddChunkWithMessages(true, 0, {"1st", "2nd"});
                break;
            case 2:
                // Add chunks to all but one of the logs.
                AddChunkWithMessages(true, 0, {"1st", "2nd"});
                AddChunkWithMessages(true, 1, {"1st", "2nd"});
                AddChunkWithMessages(true, 2, {"1st", "2nd"});
                AddChunkWithMessages(true, 3, {"1st", "2nd"});
                AddChunkWithMessages(true, 4, {"1st", "2nd"});
                AddChunkWithMessages(true, 5, {"1st", "2nd"});
                AddChunkWithMessages(true, 6, {"1st", "2nd"});
                break;
            case 3:
                // Finally add chunks to all logs.
                AddChunkWithMessages(true, 0, {"1st", "2nd"});
                AddChunkWithMessages(true, 1, {"1st", "2nd"});
                AddChunkWithMessages(true, 2, {"1st", "2nd"});
                AddChunkWithMessages(true, 3, {"1st", "2nd"});
                AddChunkWithMessages(true, 4, {"1st", "2nd"});
                AddChunkWithMessages(true, 5, {"1st", "2nd"});
                AddChunkWithMessages(true, 6, {"1st", "2nd"});
                AddChunkWithMessages(true, 7, {"1st", "2nd"});
                break;
            default:
                return false;
        }
        return true;
    };

    TestAllReadingWithFutureMessages(write_logs);
}
