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

#include <limits>
#include <optional>
#include <string_view>
#include <type_traits>

namespace android {
namespace snapshot {

struct CowOperationV3;
typedef CowOperationV3 CowOperation;

static constexpr uint64_t kCowMagicNumber = 0x436f77634f572121ULL;
static constexpr uint32_t kCowVersionMajor = 2;
static constexpr uint32_t kCowVersionMinor = 0;

static constexpr uint32_t kMinCowVersion = 1;
static constexpr uint32_t kMaxCowVersion = 3;

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
    uint64_t op_index;
} __attribute__((packed));

static constexpr uint8_t kNumResumePoints = 4;

struct CowHeaderV3 : public CowHeader {
    // Number of sequence data stored (each of which is a 32 bit integer)
    uint64_t sequence_data_count;
    // Number of currently written resume points &&
    uint32_t resume_point_count;
    // Number of max resume points that can be written
    uint32_t resume_point_max;
    // Number of CowOperationV3 structs in the operation buffer, currently and total
    // region size.
    uint64_t op_count;
    uint64_t op_count_max;
    // Compression Algorithm
    uint32_t compression_algorithm;
    // Max compression size supported
    uint32_t max_compression_size;
} __attribute__((packed));

enum class CowOperationType : uint8_t {
    kCowCopyOp = 1,
    kCowReplaceOp = 2,
    kCowZeroOp = 3,
    kCowLabelOp = 4,
    kCowClusterOp = 5,
    kCowXorOp = 6,
    kCowSequenceOp = 7,
    kCowFooterOp = std::numeric_limits<uint8_t>::max(),
};

static constexpr CowOperationType kCowCopyOp = CowOperationType::kCowCopyOp;
static constexpr CowOperationType kCowReplaceOp = CowOperationType::kCowReplaceOp;
static constexpr CowOperationType kCowZeroOp = CowOperationType::kCowZeroOp;
static constexpr CowOperationType kCowLabelOp = CowOperationType::kCowLabelOp;
static constexpr CowOperationType kCowClusterOp = CowOperationType::kCowClusterOp;
static constexpr CowOperationType kCowXorOp = CowOperationType::kCowXorOp;
static constexpr CowOperationType kCowSequenceOp = CowOperationType::kCowSequenceOp;
static constexpr CowOperationType kCowFooterOp = CowOperationType::kCowFooterOp;

// This structure is the same size of a normal Operation, but is repurposed for the footer.
struct CowFooterOperation {
    // The operation code (always kCowFooterOp).
    CowOperationType type;

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
    CowOperationType type;

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

static constexpr uint64_t kCowOpSourceInfoDataMask = (1ULL << 48) - 1;
static constexpr uint64_t kCowOpSourceInfoTypeBit = 60;
static constexpr uint64_t kCowOpSourceInfoTypeNumBits = 4;
static constexpr uint64_t kCowOpSourceInfoTypeMask = (1ULL << kCowOpSourceInfoTypeNumBits) - 1;

static constexpr uint64_t kCowOpSourceInfoCompressionBit = 57;
static constexpr uint64_t kCowOpSourceInfoCompressionNumBits = 3;
static constexpr uint64_t kCowOpSourceInfoCompressionMask =
        ((1ULL << kCowOpSourceInfoCompressionNumBits) - 1);

// The on disk format of cow (currently ==  CowOperation)
struct CowOperationV3 {
    // If this operation reads from the data section of the COW, this contains
    // the length.
    uint32_t data_length;

    // The block of data in the new image that this operation modifies.
    uint32_t new_block;

    // source_info with have the following layout
    // |--- 4 bits -- | --------- 3 bits ------ | --- 9 bits --- | --- 48 bits ---|
    // |--- type ---  | -- compression factor --| --- unused --- | --- source --- |
    //
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
    //
    // Bits [57-59] represents the compression factor.
    //
    //       Compression - factor
    // ==========================
    // 000 -  4k
    // 001 -  8k
    // 010 -  16k
    // ...
    // 110 -  256k
    //
    uint64_t source_info_;
    constexpr uint64_t source() const { return source_info_ & kCowOpSourceInfoDataMask; }
    constexpr void set_source(uint64_t source) {
        // Clear the first 48 bit first
        source_info_ &= ~kCowOpSourceInfoDataMask;
        // Set the actual source field
        source_info_ |= source & kCowOpSourceInfoDataMask;
    }
    constexpr CowOperationType type() const {
        // this is a mask to grab the first 4 bits of a 64 bit integer
        const auto type = (source_info_ >> kCowOpSourceInfoTypeBit) & kCowOpSourceInfoTypeMask;
        return static_cast<CowOperationType>(type);
    }
    constexpr void set_type(CowOperationType type) {
        // Clear the top 4 bits first
        source_info_ &= ((1ULL << kCowOpSourceInfoTypeBit) - 1);
        // set the actual type bits
        source_info_ |= (static_cast<uint64_t>(type) & kCowOpSourceInfoTypeMask)
                        << kCowOpSourceInfoTypeBit;
    }
    constexpr void set_compression_bits(uint8_t compression_factor) {
        // Clear the 3 bits from bit 57 - [57-59]
        source_info_ &= ~(kCowOpSourceInfoCompressionMask << kCowOpSourceInfoCompressionBit);
        // Set the actual compression factor
        source_info_ |=
                (static_cast<uint64_t>(compression_factor) & kCowOpSourceInfoCompressionMask)
                << kCowOpSourceInfoCompressionBit;
    }
    constexpr uint8_t compression_bits() const {
        // Grab the 3 bits from [57-59]
        const auto compression_factor =
                (source_info_ >> kCowOpSourceInfoCompressionBit) & kCowOpSourceInfoCompressionMask;
        return static_cast<uint8_t>(compression_factor);
    }
} __attribute__((packed));

// Ensure that getters/setters added to CowOperationV3 does not increases size
// of CowOperationV3 struct(no virtual method tables added).
static_assert(std::is_trivially_copyable_v<CowOperationV3>);
static_assert(std::is_standard_layout_v<CowOperationV3>);
static_assert(sizeof(CowOperationV2) == sizeof(CowFooterOperation));

enum CowCompressionAlgorithm : uint8_t {
    kCowCompressNone = 0,
    kCowCompressGz = 1,
    kCowCompressBrotli = 2,
    kCowCompressLz4 = 3,
    kCowCompressZstd = 4,
};
struct CowCompression {
    CowCompressionAlgorithm algorithm = kCowCompressNone;
    int32_t compression_level = 0;
};

static constexpr uint8_t kCowReadAheadNotStarted = 0;
static constexpr uint8_t kCowReadAheadInProgress = 1;
static constexpr uint8_t kCowReadAheadDone = 2;

static constexpr off_t GetSequenceOffset(const CowHeaderV3& header) {
    return header.prefix.header_size + header.buffer_size;
}

static constexpr off_t GetResumeOffset(const CowHeaderV3& header) {
    return GetSequenceOffset(header) + (header.sequence_data_count * sizeof(uint32_t));
}

static constexpr off_t GetOpOffset(uint32_t op_index, const CowHeaderV3& header) {
    return GetResumeOffset(header) + (header.resume_point_max * sizeof(ResumePoint)) +
           (op_index * sizeof(CowOperationV3));
}

static constexpr off_t GetDataOffset(const CowHeaderV3& header) {
    return GetOpOffset(header.op_count_max, header);
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

std::ostream& operator<<(std::ostream& os, CowOperationV3 const& arg);

std::ostream& operator<<(std::ostream& os, ResumePoint const& arg);

std::ostream& operator<<(std::ostream& os, CowOperationType cow_type);

int64_t GetNextOpOffset(const CowOperationV2& op, uint32_t cluster_size);
int64_t GetNextDataOffset(const CowOperationV2& op, uint32_t cluster_size);

// Ops that are internal to the Cow Format and not OTA data
bool IsMetadataOp(const CowOperation& op);
// Ops that have dependencies on old blocks, and must take care in their merge order
bool IsOrderedOp(const CowOperation& op);

// Convert compression name to internal value.
std::optional<CowCompressionAlgorithm> CompressionAlgorithmFromString(std::string_view name);

// Return block size used for compression
size_t CowOpCompressionSize(const CowOperation* op, size_t block_size);

// Return the relative offset of the I/O block which the CowOperation
// multi-block compression
bool GetBlockOffset(const CowOperation* op, uint64_t io_block, size_t block_size, off_t* offset);
}  // namespace snapshot
}  // namespace android
