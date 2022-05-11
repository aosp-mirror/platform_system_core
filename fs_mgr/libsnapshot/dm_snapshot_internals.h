// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <android-base/logging.h>
#include <stdint.h>

#include <limits>
#include <optional>
#include <unordered_set>

namespace android {
namespace snapshot {

class DmSnapCowSizeCalculator {
  public:
    DmSnapCowSizeCalculator(unsigned int sector_bytes, unsigned int chunk_sectors)
        : sector_bytes_(sector_bytes),
          chunk_sectors_(chunk_sectors),
          exceptions_per_chunk(chunk_sectors_ * sector_bytes_ / exception_size_bytes) {}

    void WriteByte(uint64_t address) { WriteSector(address / sector_bytes_); }
    void WriteSector(uint64_t sector) { WriteChunk(sector / chunk_sectors_); }
    void WriteChunk(uint64_t chunk_id) {
        if (!valid_) {
            return;
        }

        if (chunk_id > std::numeric_limits<uint32_t>::max()) {
            LOG(ERROR) << "Chunk exceeds maximum size: " << chunk_id;
            valid_ = false;
            return;
        }
        if (modified_chunks_.count(chunk_id) > 0) {
            return;
        }

        modified_chunks_.emplace(chunk_id);
    }

    std::optional<uint64_t> cow_size_bytes() const {
        auto sectors = cow_size_sectors();
        if (!sectors) {
            return std::nullopt;
        }
        return sectors.value() * sector_bytes_;
    }
    std::optional<uint64_t> cow_size_sectors() const {
        auto chunks = cow_size_chunks();
        if (!chunks) {
            return std::nullopt;
        }
        return chunks.value() * chunk_sectors_;
    }

    /*
     * The COW device has a precise internal structure as follows:
     *
     * - header (1 chunk)
     * - #0 map and chunks
     *   - map (1 chunk)
     *   - chunks addressable by previous map (exceptions_per_chunk)
     * - #1 map and chunks
     *   - map (1 chunk)
     *   - chunks addressable by previous map (exceptions_per_chunk)
     * ...
     * - #n: map and chunks
     *   - map (1 chunk)
     *   - chunks addressable by previous map (exceptions_per_chunk)
     * - 1 extra chunk
     */
    std::optional<uint64_t> cow_size_chunks() const {
        if (!valid_) {
            LOG(ERROR) << "Invalid COW size.";
            return std::nullopt;
        }

        uint64_t cow_chunks = 0;

        /* disk header + padding = 1 chunk */
        cow_chunks += 1;

        /* snapshot modified chunks */
        cow_chunks += modified_chunks_.size();

        /* snapshot chunks index metadata */
        cow_chunks += 1 + modified_chunks_.size() / exceptions_per_chunk;

        return cow_chunks;
    }

  private:
    /*
     * Size of each sector in bytes.
     */
    const uint64_t sector_bytes_;

    /*
     * Size of each chunk in sectors.
     */
    const uint64_t chunk_sectors_;

    /*
     * The COW device stores tables to map the modified chunks. Each table has
     * the size of exactly 1 chunk.
     * Each entry of the table is called exception and the number of exceptions
     * that each table can contain determines the number of data chunks that
     * separate two consecutive tables. This value is then fundamental to
     * compute the space overhead introduced by the tables in COW devices.
     */
    const uint64_t exceptions_per_chunk;

    /*
     * Each row of the table (called exception in the kernel) contains two
     * 64 bit indices to identify the corresponding chunk, and this 128 bit
     * pair is constant in size.
     */
    static constexpr unsigned int exception_size_bytes = 64 * 2 / 8;

    /*
     * Validity check for the container.
     * It may happen that the caller attempts the write of an invalid chunk
     * identifier, and this misbehavior is accounted and stored in this value.
     */
    bool valid_ = true;

    /*
     * |modified_chunks_| is a container that keeps trace of the modified
     * chunks.
     */
    std::unordered_set<uint32_t> modified_chunks_;
};

}  // namespace snapshot
}  // namespace android
