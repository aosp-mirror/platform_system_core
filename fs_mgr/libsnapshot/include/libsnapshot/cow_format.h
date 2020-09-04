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

#include <stdint.h>

namespace android {
namespace snapshot {

static constexpr uint64_t kCowMagicNumber = 0x436f77634f572121ULL;
static constexpr uint32_t kCowVersionMajor = 1;
static constexpr uint32_t kCowVersionMinor = 0;

// This header appears as the first sequence of bytes in the COW. All fields
// in the layout are little-endian encoded. The on-disk layout is:
//
//      +-----------------------+
//      |     Header (fixed)    |
//      +-----------------------+
//      |  Raw Data (variable)  |
//      +-----------------------+
//      | Operations (variable) |
//      +-----------------------+
//
// The "raw data" occurs immediately after the header, and the operation
// sequence occurs after the raw data. This ordering is intentional. While
// streaming an OTA, we can immediately write compressed data, but store the
// metadata in memory. At the end, we can simply append the metadata and flush
// the file. There is no need to create separate files to store the metadata
// and block data.
struct CowHeader {
    uint64_t magic;
    uint16_t major_version;
    uint16_t minor_version;

    // Offset to the location of the operation sequence, and size of the
    // operation sequence buffer. |ops_offset| is also the end of the
    // raw data region.
    uint64_t ops_offset;
    uint64_t ops_size;
    uint64_t num_ops;

    // The size of block operations, in bytes.
    uint32_t block_size;

    // SHA256 checksums of this header, with this field set to 0.
    uint8_t header_checksum[32];

    // SHA256 of the operation sequence.
    uint8_t ops_checksum[32];
} __attribute__((packed));

// Cow operations are currently fixed-size entries, but this may change if
// needed.
struct CowOperation {
    // The operation code (see the constants and structures below).
    uint8_t type;

    // If this operation reads from the data section of the COW, this contains
    // the compression type of that data (see constants below).
    uint8_t compression;

    // If this operation reads from the data section of the COW, this contains
    // the length.
    uint16_t data_length;

    // The block of data in the new image that this operation modifies.
    uint64_t new_block;

    // The value of |source| depends on the operation code.
    //
    // For copy operations, this is a block location in the source image.
    //
    // For replace operations, this is a byte offset within the COW's data
    // section (eg, not landing within the header or metadata). It is an
    // absolute position within the image.
    //
    // For zero operations (replace with all zeroes), this is unused and must
    // be zero.
    uint64_t source;
} __attribute__((packed));

static constexpr uint8_t kCowCopyOp = 1;
static constexpr uint8_t kCowReplaceOp = 2;
static constexpr uint8_t kCowZeroOp = 3;

static constexpr uint8_t kCowCompressNone = 0;
static constexpr uint8_t kCowCompressGz = 1;
static constexpr uint8_t kCowCompressBrotli = 2;

}  // namespace snapshot
}  // namespace android
