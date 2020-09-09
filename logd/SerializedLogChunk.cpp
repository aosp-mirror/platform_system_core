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

#include "SerializedLogChunk.h"

#include <android-base/logging.h>

#include "CompressionEngine.h"

SerializedLogChunk::~SerializedLogChunk() {
    CHECK_EQ(reader_ref_count_, 0U);
}

void SerializedLogChunk::Compress() {
    CHECK_EQ(compressed_log_.size(), 0U);
    CompressionEngine::GetInstance().Compress(contents_, write_offset_, compressed_log_);
    LOG(INFO) << "Compressed Log, buffer max size: " << contents_.size()
              << " size used: " << write_offset_ << " compressed size: " << compressed_log_.size();
}

// TODO: Develop a better reference counting strategy to guard against the case where the writer is
// much faster than the reader, and we needlessly compess / decompress the logs.
void SerializedLogChunk::IncReaderRefCount() {
    if (++reader_ref_count_ != 1 || writer_active_) {
        return;
    }
    contents_.Resize(write_offset_);
    CompressionEngine::GetInstance().Decompress(compressed_log_, contents_);
}

void SerializedLogChunk::DecReaderRefCount() {
    CHECK_NE(reader_ref_count_, 0U);
    if (--reader_ref_count_ != 0) {
        return;
    }
    if (!writer_active_) {
        contents_.Resize(0);
    }
}

bool SerializedLogChunk::ClearUidLogs(uid_t uid, log_id_t log_id, LogStatistics* stats) {
    CHECK_EQ(reader_ref_count_, 0U);
    if (write_offset_ == 0) {
        return true;
    }

    IncReaderRefCount();

    int read_offset = 0;
    int new_write_offset = 0;
    while (read_offset < write_offset_) {
        const auto* entry = log_entry(read_offset);
        if (entry->uid() == uid) {
            read_offset += entry->total_len();
            if (stats != nullptr) {
                stats->Subtract(entry->ToLogStatisticsElement(log_id));
            }
            continue;
        }
        size_t entry_total_len = entry->total_len();
        if (read_offset != new_write_offset) {
            memmove(contents_.data() + new_write_offset, contents_.data() + read_offset,
                    entry_total_len);
        }
        read_offset += entry_total_len;
        new_write_offset += entry_total_len;
    }

    if (new_write_offset == 0) {
        DecReaderRefCount();
        return true;
    }

    // Clear the old compressed logs and set write_offset_ appropriately to compress the new
    // partially cleared log.
    if (new_write_offset != write_offset_) {
        write_offset_ = new_write_offset;
        if (!writer_active_) {
            compressed_log_.Resize(0);
            Compress();
        }
    }

    DecReaderRefCount();

    return false;
}

bool SerializedLogChunk::CanLog(size_t len) {
    return write_offset_ + len <= contents_.size();
}

SerializedLogEntry* SerializedLogChunk::Log(uint64_t sequence, log_time realtime, uid_t uid,
                                            pid_t pid, pid_t tid, const char* msg, uint16_t len) {
    auto new_log_address = contents_.data() + write_offset_;
    auto* entry = new (new_log_address) SerializedLogEntry(uid, pid, tid, sequence, realtime, len);
    memcpy(entry->msg(), msg, len);
    write_offset_ += entry->total_len();
    highest_sequence_number_ = sequence;
    return entry;
}