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

#include <limits>

#include <android-base/logging.h>

SerializedFlushToState::SerializedFlushToState(uint64_t start, LogMask log_mask)
    : FlushToState(start, log_mask) {
    log_id_for_each(i) {
        if (((1 << i) & log_mask) == 0) {
            continue;
        }
        logs_needed_from_next_position_[i] = true;
    }
}

SerializedFlushToState::~SerializedFlushToState() {
    log_id_for_each(i) {
        if (log_positions_[i]) {
            log_positions_[i]->buffer_it->DecReaderRefCount();
        }
    }
}

void SerializedFlushToState::CreateLogPosition(log_id_t log_id) {
    CHECK(!logs_[log_id].empty());
    LogPosition log_position;
    auto it = logs_[log_id].begin();
    while (it != logs_[log_id].end() && start() > it->highest_sequence_number()) {
        ++it;
    }
    if (it == logs_[log_id].end()) {
        --it;
    }
    it->IncReaderRefCount();
    log_position.buffer_it = it;

    // Find the offset of the first log with sequence number >= start().
    int read_offset = 0;
    while (read_offset < it->write_offset()) {
        const auto* entry = it->log_entry(read_offset);
        if (entry->sequence() >= start()) {
            break;
        }
        read_offset += entry->total_len();
    }
    log_position.read_offset = read_offset;

    log_positions_[log_id].emplace(log_position);
}

void SerializedFlushToState::UpdateLogsNeeded(log_id_t log_id) {
    auto& buffer_it = log_positions_[log_id]->buffer_it;
    auto read_offset = log_positions_[log_id]->read_offset;

    // If there is another log to read in this buffer, let it be read.
    if (read_offset < buffer_it->write_offset()) {
        logs_needed_from_next_position_[log_id] = false;
    } else if (read_offset == buffer_it->write_offset()) {
        // If there are no more logs to read in this buffer and it's the last buffer, then
        // set logs_needed_from_next_position_ to wait until more logs get logged.
        if (buffer_it == std::prev(logs_[log_id].end())) {
            logs_needed_from_next_position_[log_id] = true;
        } else {
            // Otherwise, if there is another buffer piece, move to that and do the same check.
            buffer_it->DecReaderRefCount();
            ++buffer_it;
            buffer_it->IncReaderRefCount();
            log_positions_[log_id]->read_offset = 0;
            if (buffer_it->write_offset() == 0) {
                logs_needed_from_next_position_[log_id] = true;
            } else {
                logs_needed_from_next_position_[log_id] = false;
            }
        }
    } else {
        // read_offset > buffer_it->write_offset() should never happen.
        CHECK(false);
    }
}

void SerializedFlushToState::CheckForNewLogs() {
    log_id_for_each(i) {
        if (!logs_needed_from_next_position_[i]) {
            continue;
        }
        if (!log_positions_[i]) {
            if (logs_[i].empty()) {
                continue;
            }
            CreateLogPosition(i);
        }
        UpdateLogsNeeded(i);
    }
}

bool SerializedFlushToState::HasUnreadLogs() {
    CheckForNewLogs();
    log_id_for_each(i) {
        if (log_positions_[i] && !logs_needed_from_next_position_[i]) {
            return true;
        }
    }
    return false;
}

LogWithId SerializedFlushToState::PopNextUnreadLog() {
    uint64_t min_sequence = std::numeric_limits<uint64_t>::max();
    log_id_t log_id;
    const SerializedLogEntry* entry = nullptr;
    log_id_for_each(i) {
        if (!log_positions_[i] || logs_needed_from_next_position_[i]) {
            continue;
        }
        if (log_positions_[i]->log_entry()->sequence() < min_sequence) {
            log_id = i;
            entry = log_positions_[i]->log_entry();
            min_sequence = entry->sequence();
        }
    }
    CHECK_NE(nullptr, entry);

    log_positions_[log_id]->read_offset += entry->total_len();

    logs_needed_from_next_position_[log_id] = true;

    return {log_id, entry};
}

void SerializedFlushToState::Prune(log_id_t log_id,
                                   const std::list<SerializedLogChunk>::iterator& buffer_it) {
    // If we don't have a position for this log or if we're not referencing buffer_it, ignore.
    if (!log_positions_[log_id].has_value() || log_positions_[log_id]->buffer_it != buffer_it) {
        return;
    }

    // Decrease the ref count since we're deleting our reference.
    buffer_it->DecReaderRefCount();

    // Delete in the reference.
    log_positions_[log_id].reset();

    // Finally set logs_needed_from_next_position_, so CheckForNewLogs() will re-create the
    // log_position_ object during the next read.
    logs_needed_from_next_position_[log_id] = true;
}
