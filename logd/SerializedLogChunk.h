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

#include <sys/types.h>

#include "LogWriter.h"
#include "SerializedData.h"
#include "SerializedLogEntry.h"

class SerializedLogChunk {
  public:
    explicit SerializedLogChunk(size_t size) : contents_(size) {}
    SerializedLogChunk(SerializedLogChunk&& other) noexcept = default;
    ~SerializedLogChunk();

    void Compress();
    void IncReaderRefCount();
    // Decrease the reader ref count and compress the log if appropriate.  `compress` should only be
    // set to false in the case that the log buffer will be deleted afterwards.
    void DecReaderRefCount(bool compress);

    // Must have no readers referencing this.  Return true if there are no logs left in this chunk.
    bool ClearUidLogs(uid_t uid, log_id_t log_id, LogStatistics* stats);

    bool CanLog(size_t len);
    SerializedLogEntry* Log(uint64_t sequence, log_time realtime, uid_t uid, pid_t pid, pid_t tid,
                            const char* msg, uint16_t len);

    // If this buffer has been compressed, we only consider its compressed size when accounting for
    // memory consumption for pruning.  This is since the uncompressed log is only by used by
    // readers, and thus not a representation of how much these logs cost to keep in memory.
    size_t PruneSize() const {
        return sizeof(*this) + (compressed_log_.size() ?: contents_.size());
    }

    void FinishWriting() {
        writer_active_ = false;
        if (reader_ref_count_ == 0) {
            Compress();
        }
    }

    const SerializedLogEntry* log_entry(int offset) const {
        return reinterpret_cast<const SerializedLogEntry*>(data() + offset);
    }
    const uint8_t* data() const { return contents_.data(); }
    int write_offset() const { return write_offset_; }
    uint64_t highest_sequence_number() const { return highest_sequence_number_; }

    // Exposed for testing
    uint32_t reader_ref_count() const { return reader_ref_count_; }

  private:
    // The decompressed contents of this log buffer.  Deallocated when the ref_count reaches 0 and
    // writer_active_ is false.
    SerializedData contents_;
    int write_offset_ = 0;
    uint32_t reader_ref_count_ = 0;
    bool writer_active_ = true;
    uint64_t highest_sequence_number_ = 1;
    SerializedData compressed_log_;
};
