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
#include "LogReader.h"

using namespace std::placeholders;

pthread_mutex_t LogReaderThread::timesLock = PTHREAD_MUTEX_INITIALIZER;

LogReaderThread::LogReaderThread(LogReader& reader, SocketClient* client, bool non_block,
                                 unsigned long tail, unsigned int log_mask, pid_t pid,
                                 log_time start_time, uint64_t start, uint64_t timeout,
                                 bool privileged, bool can_read_security_logs)
    : leading_dropped_(false),
      reader_(reader),
      log_mask_(log_mask),
      pid_(pid),
      tail_(tail),
      count_(0),
      index_(0),
      client_(client),
      start_time_(start_time),
      start_(start),
      non_block_(non_block),
      privileged_(privileged),
      can_read_security_logs_(can_read_security_logs) {
    timeout_.tv_sec = timeout / NS_PER_SEC;
    timeout_.tv_nsec = timeout % NS_PER_SEC;
    memset(last_tid_, 0, sizeof(last_tid_));
    pthread_cond_init(&thread_triggered_condition_, nullptr);
    cleanSkip_Locked();
}

bool LogReaderThread::startReader_Locked() {
    auto thread = std::thread{&LogReaderThread::ThreadFunction, this};
    thread.detach();
    return true;
}

void LogReaderThread::ThreadFunction() {
    prctl(PR_SET_NAME, "logd.reader.per");

    SocketClient* client = client_;

    LogBuffer& logbuf = reader_.logbuf();

    leading_dropped_ = true;

    wrlock();

    uint64_t start = start_;

    while (!release_) {
        if (timeout_.tv_sec || timeout_.tv_nsec) {
            if (pthread_cond_clockwait(&thread_triggered_condition_, &timesLock, CLOCK_MONOTONIC,
                                       &timeout_) == ETIMEDOUT) {
                timeout_.tv_sec = 0;
                timeout_.tv_nsec = 0;
            }
            if (release_) {
                break;
            }
        }

        unlock();

        if (tail_) {
            logbuf.flushTo(client, start, nullptr, privileged_, can_read_security_logs_,
                           std::bind(&LogReaderThread::FilterFirstPass, this, _1));
            leading_dropped_ =
                    true;  // TODO: Likely a bug, if leading_dropped_ was not true before calling
                           // flushTo(), then it should not be reset to true after.
        }
        start = logbuf.flushTo(client, start, last_tid_, privileged_, can_read_security_logs_,
                               std::bind(&LogReaderThread::FilterSecondPass, this, _1));

        // We only ignore entries before the original start time for the first flushTo(), if we
        // get entries after this first flush before the original start time, then the client
        // wouldn't have seen them.
        // Note: this is still racy and may skip out of order events that came in since the last
        // time the client disconnected and then reconnected with the new start time.  The long term
        // solution here is that clients must request events since a specific sequence number.
        start_time_.tv_sec = 0;
        start_time_.tv_nsec = 0;

        wrlock();

        if (start == LogBufferElement::FLUSH_ERROR) {
            break;
        }

        start_ = start + 1;

        if (non_block_ || release_) {
            break;
        }

        cleanSkip_Locked();

        if (!timeout_.tv_sec && !timeout_.tv_nsec) {
            pthread_cond_wait(&thread_triggered_condition_, &timesLock);
        }
    }

    LogReader& reader = reader_;
    reader.release(client);

    client->decRef();

    LastLogTimes& times = reader.logbuf().mTimes;
    auto it = std::find_if(times.begin(), times.end(),
                           [this](const auto& other) { return other.get() == this; });

    if (it != times.end()) {
        times.erase(it);
    }

    unlock();
}

// A first pass to count the number of elements
int LogReaderThread::FilterFirstPass(const LogBufferElement* element) {
    LogReaderThread::wrlock();

    if (leading_dropped_) {
        if (element->getDropped()) {
            LogReaderThread::unlock();
            return false;
        }
        leading_dropped_ = false;
    }

    if (count_ == 0) {
        start_ = element->getSequence();
    }

    if ((!pid_ || pid_ == element->getPid()) && IsWatching(element->getLogId()) &&
        (start_time_ == log_time::EPOCH || start_time_ <= element->getRealTime())) {
        ++count_;
    }

    LogReaderThread::unlock();

    return false;
}

// A second pass to send the selected elements
int LogReaderThread::FilterSecondPass(const LogBufferElement* element) {
    LogReaderThread::wrlock();

    start_ = element->getSequence();

    if (skip_ahead_[element->getLogId()]) {
        skip_ahead_[element->getLogId()]--;
        goto skip;
    }

    if (leading_dropped_) {
        if (element->getDropped()) {
            goto skip;
        }
        leading_dropped_ = false;
    }

    // Truncate to close race between first and second pass
    if (non_block_ && tail_ && index_ >= count_) {
        goto stop;
    }

    if (!IsWatching(element->getLogId())) {
        goto skip;
    }

    if (pid_ && pid_ != element->getPid()) {
        goto skip;
    }

    if (start_time_ != log_time::EPOCH && element->getRealTime() <= start_time_) {
        goto skip;
    }

    if (release_) {
        goto stop;
    }

    if (!tail_) {
        goto ok;
    }

    ++index_;

    if (count_ > tail_ && index_ <= (count_ - tail_)) {
        goto skip;
    }

    if (!non_block_) {
        tail_ = 0;
    }

ok:
    if (!skip_ahead_[element->getLogId()]) {
        LogReaderThread::unlock();
        return true;
    }
    // FALLTHRU

skip:
    LogReaderThread::unlock();
    return false;

stop:
    LogReaderThread::unlock();
    return -1;
}

void LogReaderThread::cleanSkip_Locked(void) {
    memset(skip_ahead_, 0, sizeof(skip_ahead_));
}
