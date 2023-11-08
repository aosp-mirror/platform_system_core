// Copyright (C) 2023 The Android Open Source Project
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
#include "parser_v3.h"

#include <android-base/file.h>
#include <android-base/logging.h>

#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

using android::base::borrowed_fd;

bool CowParserV3::Parse(borrowed_fd fd, const CowHeaderV3& header, std::optional<uint64_t> label) {
    auto pos = lseek(fd.get(), 0, SEEK_END);
    if (pos < 0) {
        PLOG(ERROR) << "lseek end failed";
        return false;
    }
    fd_size_ = pos;
    header_ = header;

    if (header_.footer_size != 0) {
        LOG(ERROR) << "Footer size isn't 0, read " << header_.footer_size;
        return false;
    }
    if (header_.op_size != sizeof(CowOperationV3)) {
        LOG(ERROR) << "Operation size unknown, read " << header_.op_size << ", expected "
                   << sizeof(CowOperationV3);
        return false;
    }
    if (header_.cluster_ops != 0) {
        LOG(ERROR) << "Cluster ops not supported in v3";
        return false;
    }

    if (header_.prefix.major_version != 3 || header_.prefix.minor_version != 0) {
        LOG(ERROR) << "Header version mismatch, "
                   << "major version: " << header_.prefix.major_version
                   << ", expected: " << kCowVersionMajor
                   << ", minor version: " << header_.prefix.minor_version
                   << ", expected: " << kCowVersionMinor;
        return false;
    }

    return ParseOps(fd, label);
}

off_t CowParserV3::GetDataOffset() const {
    return sizeof(CowHeaderV3) + header_.buffer_size + header_.op_count_max * sizeof(CowOperation);
}

bool CowParserV3::ParseOps(borrowed_fd fd, std::optional<uint64_t> label) {
    ops_ = std::make_shared<std::vector<CowOperationV3>>();
    ops_->resize(header_.op_count);

    const off_t offset = header_.prefix.header_size + header_.buffer_size;
    if (!android::base::ReadFullyAtOffset(fd, ops_->data(), ops_->size() * sizeof(CowOperationV3),
                                          offset)) {
        PLOG(ERROR) << "read ops failed";
        return false;
    }

    // fill out mapping of XOR op data location
    uint64_t data_pos = GetDataOffset();

    xor_data_loc_ = std::make_shared<std::unordered_map<uint64_t, uint64_t>>();

    for (auto op : *ops_) {
        if (op.type == kCowXorOp) {
            xor_data_loc_->insert({op.new_block, data_pos});
        }
        data_pos += op.data_length;
    }
    // :TODO: sequence buffer & resume buffer follow
    // Once we implement labels, we'll have to discard unused ops and adjust
    // the header as needed.
    CHECK(!label);

    ops_->shrink_to_fit();

    return true;
}

bool CowParserV3::Translate(TranslatedCowOps* out) {
    out->ops = ops_;
    out->header = header_;
    return true;
}

}  // namespace snapshot
}  // namespace android
