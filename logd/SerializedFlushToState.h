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

#include <bitset>
#include <list>
#include <queue>

#include "LogBuffer.h"
#include "SerializedLogChunk.h"
#include "SerializedLogEntry.h"

struct LogPosition {
    std::list<SerializedLogChunk>::iterator buffer_it;
    int read_offset;

    const SerializedLogEntry* log_entry() const { return buffer_it->log_entry(read_offset); }
};

struct LogWithId {
    log_id_t log_id;
    const SerializedLogEntry* entry;
};

// This class tracks the specific point where a FlushTo client has read through the logs.  It
// directly references the std::list<> iterators from the parent SerializedLogBuffer and the offset
// into each log chunk where it has last read.  All interactions with this class, except for its
// construction, must be done with SerializedLogBuffer::lock_ held.
class SerializedFlushToState : public FlushToState {
  public:
    // Initializes this state object.  For each log buffer set in log_mask, this sets
    // logs_needed_from_next_position_.
    SerializedFlushToState(uint64_t start, LogMask log_mask);

    // Decrease the reference of all referenced logs.  This happens when a reader is disconnected.
    ~SerializedFlushToState() override;

    // We can't hold SerializedLogBuffer::lock_ in the constructor, so we must initialize logs here.
    void InitializeLogs(std::list<SerializedLogChunk>* logs) {
        if (logs_ == nullptr) logs_ = logs;
    }

    // Updates the state of log_positions_ and logs_needed_from_next_position_ then returns true if
    // there are any unread logs, false otherwise.
    bool HasUnreadLogs();

    // Returns the next unread log and sets logs_needed_from_next_position_ to indicate that we're
    // waiting for more logs from the associated log buffer.
    LogWithId PopNextUnreadLog();

    // If the parent log buffer prunes logs, the reference that this class contains may become
    // invalid, so this must be called first to drop the reference to buffer_it, if any.
    void Prune(log_id_t log_id, const std::list<SerializedLogChunk>::iterator& buffer_it);

  private:
    // Set logs_needed_from_next_position_[i] to indicate if log_positions_[i] points to an unread
    // log or to the point at which the next log will appear.
    void UpdateLogsNeeded(log_id_t log_id);

    // Create a LogPosition object for the given log_id by searching through the log chunks for the
    // first chunk and then first log entry within that chunk that is greater or equal to start().
    void CreateLogPosition(log_id_t log_id);

    // Checks to see if any log buffers set in logs_needed_from_next_position_ have new logs and
    // calls UpdateLogsNeeded() if so.
    void CheckForNewLogs();

    std::list<SerializedLogChunk>* logs_ = nullptr;
    // An optional structure that contains an iterator to the serialized log buffer and offset into
    // it that this logger should handle next.
    std::optional<LogPosition> log_positions_[LOG_ID_MAX];
    // A bit for each log that is set if a given log_id has no logs or if this client has read all
    // of its logs. In order words: `logs_[i].empty() || (buffer_it == std::prev(logs_.end) &&
    // next_log_position == logs_write_position_)`.  These will be re-checked in each
    // loop in case new logs came in.
    std::bitset<LOG_ID_MAX> logs_needed_from_next_position_ = {};
};
