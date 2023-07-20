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
#include "writer_v2.h"

namespace android {
namespace snapshot {

using android::base::unique_fd;

std::ostream& operator<<(std::ostream& os, CowOperation const& op) {
    os << "CowOperation(type:";
    if (op.type == kCowCopyOp)
        os << "kCowCopyOp,    ";
    else if (op.type == kCowReplaceOp)
        os << "kCowReplaceOp, ";
    else if (op.type == kCowZeroOp)
        os << "kZeroOp,       ";
    else if (op.type == kCowFooterOp)
        os << "kCowFooterOp,  ";
    else if (op.type == kCowLabelOp)
        os << "kCowLabelOp,   ";
    else if (op.type == kCowClusterOp)
        os << "kCowClusterOp  ";
    else if (op.type == kCowXorOp)
        os << "kCowXorOp      ";
    else if (op.type == kCowSequenceOp)
        os << "kCowSequenceOp ";
    else if (op.type == kCowFooterOp)
        os << "kCowFooterOp  ";
    else
        os << (int)op.type << "?,";
    os << "compression:";
    if (op.compression == kCowCompressNone)
        os << "kCowCompressNone,   ";
    else if (op.compression == kCowCompressGz)
        os << "kCowCompressGz,     ";
    else if (op.compression == kCowCompressBrotli)
        os << "kCowCompressBrotli, ";
    else
        os << (int)op.compression << "?, ";
    os << "data_length:" << op.data_length << ",\t";
    os << "new_block:" << op.new_block << ",\t";
    os << "source:" << op.source;
    os << ")";
    return os;
}

int64_t GetNextOpOffset(const CowOperation& op, uint32_t cluster_ops) {
    if (op.type == kCowClusterOp) {
        return op.source;
    } else if ((op.type == kCowReplaceOp || op.type == kCowXorOp) && cluster_ops == 0) {
        return op.data_length;
    } else {
        return 0;
    }
}

int64_t GetNextDataOffset(const CowOperation& op, uint32_t cluster_ops) {
    if (op.type == kCowClusterOp) {
        return cluster_ops * sizeof(CowOperation);
    } else if (cluster_ops == 0) {
        return sizeof(CowOperation);
    } else {
        return 0;
    }
}

bool IsMetadataOp(const CowOperation& op) {
    switch (op.type) {
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
    switch (op.type) {
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

}  // namespace snapshot
}  // namespace android
