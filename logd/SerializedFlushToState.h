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
};

struct MinHeapElement {
    MinHeapElement(log_id_t log_id, const SerializedLogEntry* entry)
        : log_id(log_id), entry(entry) {}
    log_id_t log_id;
    const SerializedLogEntry* entry;
    // The change of comparison operators is intentional, std::priority_queue uses operator<() to
    // compare but creates a max heap.  Since we want a min heap, we return the opposite result.
    bool operator<(const MinHeapElement& rhs) const {
        return entry->sequence() > rhs.entry->sequence();
    }
};

// This class tracks the specific point where a FlushTo client has read through the logs.  It
// directly references the std::list<> iterators from the parent SerializedLogBuffer and the offset
// into each log chunk where it has last read.  All interactions with this class, except for its
// construction, must be done with SerializedLogBuffer::lock_ held.  No log chunks that it
// references may be pruned, which is handled by ensuring prune does not touch any log chunk with
// highest sequence number greater or equal to start().
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

    // Checks to see if any log buffers set in logs_needed_from_next_position_ have new logs and
    // calls AddMinHeapEntry() if so.
    void CheckForNewLogs();

    bool HasUnreadLogs() { return !min_heap_.empty(); }

    // Pops the next unread log from the min heap.  Add the next log for that log_id to the min heap
    // if one is available otherwise set logs_needed_from_next_position_ to indicate that we're
    // waiting for more logs.
    MinHeapElement PopNextUnreadLog();

    // If the parent log buffer prunes logs, the reference that this class contains may become
    // invalid, so this must be called first to drop the reference to buffer_it, if any.
    void Prune(log_id_t log_id, const std::list<SerializedLogChunk>::iterator& buffer_it);

  private:
    // If there is a log in the serialized log buffer for `log_id` at the read_offset, add it to the
    // min heap for reading, otherwise set logs_needed_from_next_position_ to indicate that we're
    // waiting for the next log.
    void AddMinHeapEntry(log_id_t log_id);

    // Create a LogPosition object for the given log_id by searching through the log chunks for the
    // first chunk and then first log entry within that chunk that is greater or equal to start().
    void CreateLogPosition(log_id_t log_id);

    std::list<SerializedLogChunk>* logs_ = nullptr;
    // An optional structure that contains an iterator to the serialized log buffer and offset into
    // it that this logger should handle next.
    std::optional<LogPosition> log_positions_[LOG_ID_MAX];
    // A bit for each log that is set if a given log_id has no logs or if this client has read all
    // of its logs. In order words: `logs_[i].empty() || (buffer_it == std::prev(logs_.end) &&
    // next_log_position == logs_write_position_)`.  These will be re-checked in each
    // loop in case new logs came in.
    std::bitset<LOG_ID_MAX> logs_needed_from_next_position_ = {};
    // A min heap that has up to one entry per log buffer, sorted by sequence number, of the next
    // element that this reader should read.
    std::priority_queue<MinHeapElement> min_heap_;
};
