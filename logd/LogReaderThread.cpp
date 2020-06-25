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

#include "LogReaderThread.h"

#include <errno.h>
#include <string.h>
#include <sys/prctl.h>

#include <thread>

#include "LogBuffer.h"
#include "LogReaderList.h"

LogReaderThread::LogReaderThread(LogBuffer* log_buffer, LogReaderList* reader_list,
                                 std::unique_ptr<LogWriter> writer, bool non_block,
                                 unsigned long tail, LogMask log_mask, pid_t pid,
                                 log_time start_time, uint64_t start,
                                 std::chrono::steady_clock::time_point deadline)
    : log_buffer_(log_buffer),
      reader_list_(reader_list),
      writer_(std::move(writer)),
      pid_(pid),
      tail_(tail),
      count_(0),
      index_(0),
      start_time_(start_time),
      deadline_(deadline),
      non_block_(non_block) {
    cleanSkip_Locked();
    flush_to_state_ = log_buffer_->CreateFlushToState(start, log_mask);
    auto thread = std::thread{&LogReaderThread::ThreadFunction, this};
    thread.detach();
}

void LogReaderThread::ThreadFunction() {
    prctl(PR_SET_NAME, "logd.reader.per");

    auto lock = std::unique_lock{reader_list_->reader_threads_lock()};

    while (!release_) {
        if (deadline_.time_since_epoch().count() != 0) {
            if (thread_triggered_condition_.wait_until(lock, deadline_) ==
                std::cv_status::timeout) {
                deadline_ = {};
            }
            if (release_) {
                break;
            }
        }

        lock.unlock();

        if (tail_) {
            auto first_pass_state = log_buffer_->CreateFlushToState(flush_to_state_->start(),
                                                                    flush_to_state_->log_mask());
            log_buffer_->FlushTo(
                    writer_.get(), *first_pass_state,
                    [this](log_id_t log_id, pid_t pid, uint64_t sequence, log_time realtime) {
                        return FilterFirstPass(log_id, pid, sequence, realtime);
                    });
        }
        bool flush_success = log_buffer_->FlushTo(
                writer_.get(), *flush_to_state_,
                [this](log_id_t log_id, pid_t pid, uint64_t sequence, log_time realtime) {
                    return FilterSecondPass(log_id, pid, sequence, realtime);
                });

        // We only ignore entries before the original start time for the first flushTo(), if we
        // get entries after this first flush before the original start time, then the client
        // wouldn't have seen them.
        // Note: this is still racy and may skip out of order events that came in since the last
        // time the client disconnected and then reconnected with the new start time.  The long term
        // solution here is that clients must request events since a specific sequence number.
        start_time_.tv_sec = 0;
        start_time_.tv_nsec = 0;

        lock.lock();

        if (!flush_success) {
            break;
        }

        if (non_block_ || release_) {
            break;
        }

        cleanSkip_Locked();

        if (deadline_.time_since_epoch().count() == 0) {
            thread_triggered_condition_.wait(lock);
        }
    }

    writer_->Release();

    auto& log_reader_threads = reader_list_->reader_threads();
    auto it = std::find_if(log_reader_threads.begin(), log_reader_threads.end(),
                           [this](const auto& other) { return other.get() == this; });

    if (it != log_reader_threads.end()) {
        log_reader_threads.erase(it);
    }
}

// A first pass to count the number of elements
FilterResult LogReaderThread::FilterFirstPass(log_id_t, pid_t pid, uint64_t, log_time realtime) {
    auto lock = std::lock_guard{reader_list_->reader_threads_lock()};

    if ((!pid_ || pid_ == pid) && (start_time_ == log_time::EPOCH || start_time_ <= realtime)) {
        ++count_;
    }

    return FilterResult::kSkip;
}

// A second pass to send the selected elements
FilterResult LogReaderThread::FilterSecondPass(log_id_t log_id, pid_t pid, uint64_t,
                                               log_time realtime) {
    auto lock = std::lock_guard{reader_list_->reader_threads_lock()};

    if (skip_ahead_[log_id]) {
        skip_ahead_[log_id]--;
        return FilterResult::kSkip;
    }

    // Truncate to close race between first and second pass
    if (non_block_ && tail_ && index_ >= count_) {
        return FilterResult::kStop;
    }

    if (pid_ && pid_ != pid) {
        return FilterResult::kSkip;
    }

    if (start_time_ != log_time::EPOCH && realtime <= start_time_) {
        return FilterResult::kSkip;
    }

    if (release_) {
        return FilterResult::kStop;
    }

    if (!tail_) {
        goto ok;
    }

    ++index_;

    if (count_ > tail_ && index_ <= (count_ - tail_)) {
        return FilterResult::kSkip;
    }

    if (!non_block_) {
        tail_ = 0;
    }

ok:
    if (!skip_ahead_[log_id]) {
        return FilterResult::kWrite;
    }
    return FilterResult::kSkip;
}

void LogReaderThread::cleanSkip_Locked(void) {
    memset(skip_ahead_, 0, sizeof(skip_ahead_));
}
