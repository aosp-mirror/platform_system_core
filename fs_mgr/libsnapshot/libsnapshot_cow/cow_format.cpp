//
// Copyright (C) 2020 The Android Open Source Project
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
//

#include <libsnapshot/cow_format.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <libsnapshot/cow_format.h>
#include <storage_literals/storage_literals.h>
#include "writer_v2.h"
#include "writer_v3.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;
using namespace android::storage_literals;

std::ostream& EmitCowTypeString(std::ostream& os, CowOperationType cow_type) {
    switch (cow_type) {
        case kCowCopyOp:
            return os << "kCowCopyOp";
        case kCowReplaceOp:
            return os << "kCowReplaceOp";
        case kCowZeroOp:
            return os << "kZeroOp";
        case kCowFooterOp:
            return os << "kCowFooterOp";
        case kCowLabelOp:
            return os << "kCowLabelOp";
        case kCowClusterOp:
            return os << "kCowClusterOp";
        case kCowXorOp:
            return os << "kCowXorOp";
        case kCowSequenceOp:
            return os << "kCowSequenceOp";
        default:
            return os << (int)cow_type << "unknown";
    }
}

std::ostream& operator<<(std::ostream& os, CowOperationType cow_type) {
    return EmitCowTypeString(os, cow_type);
}

std::ostream& operator<<(std::ostream& os, CowOperationV2 const& op) {
    os << "CowOperationV2(";
    EmitCowTypeString(os, op.type) << ", ";
    switch (op.compression) {
        case kCowCompressNone:
            os << "uncompressed, ";
            break;
        case kCowCompressGz:
            os << "gz, ";
            break;
        case kCowCompressBrotli:
            os << "brotli, ";
            break;
        case kCowCompressLz4:
            os << "lz4, ";
            break;
        case kCowCompressZstd:
            os << "zstd, ";
            break;
    }
    os << "data_length:" << op.data_length << ", ";
    os << "new_block:" << op.new_block << ", ";
    os << "source:" << op.source;
    os << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, CowOperationV3 const& op) {
    os << "CowOperation(";
    EmitCowTypeString(os, op.type());
    if (op.type() == kCowReplaceOp || op.type() == kCowXorOp || op.type() == kCowSequenceOp) {
        os << ", data_length:" << op.data_length;
    }
    if (op.type() != kCowClusterOp && op.type() != kCowSequenceOp && op.type() != kCowLabelOp) {
        os << ", new_block:" << op.new_block;
    }
    if (op.type() == kCowXorOp || op.type() == kCowReplaceOp || op.type() == kCowCopyOp) {
        os << ", source:" << op.source();
    } else if (op.type() == kCowClusterOp) {
        os << ", cluster_data:" << op.source();
    }
    // V3 op stores resume points in header, so CowOp can never be Label.
    os << ")";
    return os;
}

std::ostream& operator<<(std::ostream& os, ResumePoint const& resume_point) {
    os << "ResumePoint(" << resume_point.label << " , " << resume_point.op_index << ")";
    return os;
}

int64_t GetNextOpOffset(const CowOperationV2& op, uint32_t cluster_ops) {
    if (op.type == kCowClusterOp) {
        return op.source;
    } else if ((op.type == kCowReplaceOp || op.type == kCowXorOp) && cluster_ops == 0) {
        return op.data_length;
    } else {
        return 0;
    }
}

int64_t GetNextDataOffset(const CowOperationV2& op, uint32_t cluster_ops) {
    if (op.type == kCowClusterOp) {
        return cluster_ops * sizeof(CowOperationV2);
    } else if (cluster_ops == 0) {
        return sizeof(CowOperationV2);
    } else {
        return 0;
    }
}

bool IsMetadataOp(const CowOperation& op) {
    switch (op.type()) {
        case kCowLabelOp:
        case kCowClusterOp:
        case kCowFooterOp:
        case kCowSequenceOp:
            return true;
        default:
            return false;
    }
}

bool IsOrderedOp(const CowOperation& op) {
    switch (op.type()) {
        case kCowCopyOp:
        case kCowXorOp:
            return true;
        default:
            return false;
    }
}

std::unique_ptr<ICowWriter> CreateCowWriter(uint32_t version, const CowOptions& options,
                                            unique_fd&& fd, std::optional<uint64_t> label) {
    std::unique_ptr<CowWriterBase> base;
    switch (version) {
        case 1:
        case 2:
            base = std::make_unique<CowWriterV2>(options, std::move(fd));
            break;
        case 3:
            base = std::make_unique<CowWriterV3>(options, std::move(fd));
            break;
        default:
            LOG(ERROR) << "Cannot create unknown cow version: " << version;
            return nullptr;
    }
    if (!base->Initialize(label)) {
        return nullptr;
    }
    return base;
}

std::unique_ptr<ICowWriter> CreateCowEstimator(uint32_t version, const CowOptions& options) {
    return CreateCowWriter(version, options, unique_fd{-1}, std::nullopt);
}

size_t CowOpCompressionSize(const CowOperation* op, size_t block_size) {
    uint8_t compression_bits = op->compression_bits();
    return (block_size << compression_bits);
}

bool GetBlockOffset(const CowOperation* op, uint64_t io_block, size_t block_size, off_t* offset) {
    const uint64_t new_block = op->new_block;

    if (op->type() != kCowReplaceOp || io_block < new_block) {
        LOG(VERBOSE) << "Invalid IO request for block: " << io_block
                     << " CowOperation: new_block: " << new_block;
        return false;
    }

    // Get the actual compression size
    const size_t compression_size = CowOpCompressionSize(op, block_size);
    // Find the number of blocks spanned
    const size_t num_blocks = compression_size / block_size;
    // Find the distance of the I/O block which this
    // CowOperation encompasses
    const size_t block_distance = io_block - new_block;
    // Check if this block is within this range;
    // if so, return the relative offset
    if (block_distance < num_blocks) {
        *offset = block_distance * block_size;
        return true;
    }

    return false;
}

}  // namespace snapshot
}  // namespace android
