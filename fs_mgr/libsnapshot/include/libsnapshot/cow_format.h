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

#include <optional>
#include <string_view>

namespace android {
namespace snapshot {

struct CowOperationV3;
typedef CowOperationV3 CowOperation;

static constexpr uint64_t kCowMagicNumber = 0x436f77634f572121ULL;
static constexpr uint32_t kCowVersionMajor = 2;
static constexpr uint32_t kCowVersionMinor = 0;

static constexpr uint32_t kCowVersionManifest = 2;

static constexpr uint32_t kMinCowVersion = 1;
static constexpr uint32_t kMaxCowVersion = 2;

// Normally, this should be kMaxCowVersion. When a new version is under testing
// it may be the previous value of kMaxCowVersion.
static constexpr uint32_t kDefaultCowVersion = 2;

// This header appears as the first sequence of bytes in the COW. All fields
// in the layout are little-endian encoded. The on-disk layout is:
//
//      +-----------------------+
//      |     Header (fixed)    |
//      +-----------------------+
//      |     Scratch space     |
//      +-----------------------+
//      | Operation  (variable) |
//      | Data       (variable) |
//      +-----------------------+
//      |    Footer (fixed)     |
//      +-----------------------+
//
// After the header is a 2mb scratch space that is used to read ahead data during merge operations
//
// The operations begin immediately after the scratch space, and the "raw data"
// immediately follows the operation which refers to it. While streaming
// an OTA, we can immediately write the op and data, syncing after each pair,
// while storing operation metadata in memory. At the end, we compute data and
// hashes for the footer, which is placed at the tail end of the file.
//
// A missing or corrupt footer likely indicates that writing was cut off
// between writing the last operation/data pair, or the footer itself. In this
// case, the safest way to proceed is to assume the last operation is faulty.

struct CowHeaderPrefix {
    uint64_t magic;
    uint16_t major_version;
    uint16_t minor_version;
    uint16_t header_size;  // size of CowHeader.
} __attribute__((packed));

struct CowHeader {
    CowHeaderPrefix prefix;

    // Size of footer struct
    uint16_t footer_size;

    // Size of op struct
    uint16_t op_size;

    // The size of block operations, in bytes.
    uint32_t block_size;

    // The number of ops to cluster together. 0 For no clustering. Cannot be 1.
    uint32_t cluster_ops;

    // Tracks merge operations completed
    uint64_t num_merge_ops;

    // Scratch space used during merge
    uint32_t buffer_size;

} __attribute__((packed));

// Resume point structure used for resume buffer
struct ResumePoint {
    // monotonically increasing value used by update_engine
    uint64_t label;
    // Index of last CowOperation guaranteed to be resumable
    uint32_t op_index;
} __attribute__((packed));

static constexpr uint8_t kNumResumePoints = 4;

struct CowHeaderV3 : public CowHeader {
    // Number of sequence data stored (each of which is a 32 byte integer)
    uint64_t sequence_data_count;
    // number of currently written resume points
    uint32_t resume_point_count;
    // Size, in bytes, of the CowResumePoint buffer.
    uint32_t resume_point_max;
    // Number of CowOperationV3 structs in the operation buffer, currently and total
    // region size.
    uint32_t op_count;
    uint32_t op_count_max;
    // Compression Algorithm
    uint32_t compression_algorithm;
} __attribute__((packed));

// This structure is the same size of a normal Operation, but is repurposed for the footer.
struct CowFooterOperation {
    // The operation code (always kCowFooterOp).
    uint8_t type;

    // If this operation reads from the data section of the COW, this contains
    // the compression type of that data (see constants below).
    uint8_t compression;

    // Length of Footer Data. Currently 64.
    uint16_t data_length;

    // The amount of file space used by Cow operations
    uint64_t ops_size;

    // The number of cow operations in the file
    uint64_t num_ops;
} __attribute__((packed));

// V2 version of COW. On disk format for older devices
struct CowOperationV2 {
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
    // sections (eg, not landing within the header or metadata). It is an
    // absolute position within the image.
    //
    // For zero operations (replace with all zeroes), this is unused and must
    // be zero.
    //
    // For Label operations, this is the value of the applied label.
    //
    // For Cluster operations, this is the length of the following data region
    //
    // For Xor operations, this is the byte location in the source image.
    uint64_t source;
} __attribute__((packed));

// The on disk format of cow (currently ==  CowOperation)
struct CowOperationV3 {
    // The operation code (see the constants and structures below).
    uint8_t type;

    // If this operation reads from the data section of the COW, this contains
    // the length.
    uint16_t data_length;

    // The block of data in the new image that this operation modifies.
    uint32_t new_block;

    // The value of |source| depends on the operation code.
    //
    // CopyOp: a 32-bit block location in the source image.
    // ReplaceOp: an absolute byte offset within the COW's data section.
    // XorOp: an absolute byte offset in the source image.
    // ZeroOp: unused
    // LabelOp: a 64-bit opaque identifier.
    //
    // For ops other than Label:
    //  Bits 47-62 are reserved and must be zero.
    // A block is compressed if it’s data is < block_sz
    uint64_t source_info;
} __attribute__((packed));

static_assert(sizeof(CowOperationV2) == sizeof(CowFooterOperation));

static constexpr uint8_t kCowCopyOp = 1;
static constexpr uint8_t kCowReplaceOp = 2;
static constexpr uint8_t kCowZeroOp = 3;
static constexpr uint8_t kCowLabelOp = 4;
static constexpr uint8_t kCowClusterOp = 5;
static constexpr uint8_t kCowXorOp = 6;
static constexpr uint8_t kCowSequenceOp = 7;
static constexpr uint8_t kCowFooterOp = -1;

enum CowCompressionAlgorithm : uint8_t {
    kCowCompressNone = 0,
    kCowCompressGz = 1,
    kCowCompressBrotli = 2,
    kCowCompressLz4 = 3,
    kCowCompressZstd = 4,
};
struct CowCompression {
    CowCompressionAlgorithm algorithm = kCowCompressNone;
    uint32_t compression_level = 0;
};

static constexpr uint8_t kCowReadAheadNotStarted = 0;
static constexpr uint8_t kCowReadAheadInProgress = 1;
static constexpr uint8_t kCowReadAheadDone = 2;

static constexpr uint64_t kCowOpSourceInfoDataMask = (1ULL << 48) - 1;

static inline uint64_t GetCowOpSourceInfoData(const CowOperation& op) {
    return op.source_info & kCowOpSourceInfoDataMask;
}

static constexpr off_t GetOpOffset(uint32_t op_index, const CowHeaderV3 header) {
    return header.prefix.header_size + header.buffer_size +
           (header.resume_point_max * sizeof(ResumePoint)) + (op_index * sizeof(CowOperationV3));
}
static constexpr off_t GetDataOffset(const CowHeaderV3 header) {
    return header.prefix.header_size + header.buffer_size +
           (header.resume_point_max * sizeof(ResumePoint)) +
           header.op_count_max * sizeof(CowOperation);
}
static constexpr off_t GetResumeOffset(const CowHeaderV3 header) {
    return header.prefix.header_size + header.buffer_size;
}

struct CowFooter {
    CowFooterOperation op;
    uint8_t unused[64];
} __attribute__((packed));

struct ScratchMetadata {
    // Block of data in the image that operation modifies
    // and read-ahead thread stores the modified data
    // in the scratch space
    uint64_t new_block;
    // Offset within the file to read the data
    uint64_t file_offset;
} __attribute__((packed));

struct BufferState {
    uint8_t read_ahead_state;
} __attribute__((packed));

// 2MB Scratch space used for read-ahead
static constexpr uint64_t BUFFER_REGION_DEFAULT_SIZE = (1ULL << 21);

std::ostream& operator<<(std::ostream& os, CowOperationV2 const& arg);

std::ostream& operator<<(std::ostream& os, CowOperation const& arg);

std::ostream& operator<<(std::ostream& os, ResumePoint const& arg);

int64_t GetNextOpOffset(const CowOperationV2& op, uint32_t cluster_size);
int64_t GetNextDataOffset(const CowOperationV2& op, uint32_t cluster_size);

// Ops that are internal to the Cow Format and not OTA data
bool IsMetadataOp(const CowOperation& op);
// Ops that have dependencies on old blocks, and must take care in their merge order
bool IsOrderedOp(const CowOperation& op);

// Convert compression name to internal value.
std::optional<CowCompressionAlgorithm> CompressionAlgorithmFromString(std::string_view name);

}  // namespace snapshot
}  // namespace android
