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
#include "parser_v2.h"

#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>

#include <libsnapshot/cow_format.h>

namespace android {
namespace snapshot {

using android::base::borrowed_fd;

bool CowParserV2::Parse(borrowed_fd fd, const CowHeaderV3& header, std::optional<uint64_t> label) {
    auto pos = lseek(fd.get(), 0, SEEK_END);
    if (pos < 0) {
        PLOG(ERROR) << "lseek end failed";
        return false;
    }
    fd_size_ = pos;
    header_ = header;

    if (header_.footer_size != sizeof(CowFooter)) {
        LOG(ERROR) << "Footer size unknown, read " << header_.footer_size << ", expected "
                   << sizeof(CowFooter);
        return false;
    }
    if (header_.op_size != sizeof(CowOperationV2)) {
        LOG(ERROR) << "Operation size unknown, read " << header_.op_size << ", expected "
                   << sizeof(CowOperationV2);
        return false;
    }
    if (header_.cluster_ops == 1) {
        LOG(ERROR) << "Clusters must contain at least two operations to function.";
        return false;
    }

    if (header_.prefix.major_version > 2 || header_.prefix.minor_version != 0) {
        LOG(ERROR) << "Header version mismatch, "
                   << "major version: " << header_.prefix.major_version
                   << ", expected: " << kCowVersionMajor
                   << ", minor version: " << header_.prefix.minor_version
                   << ", expected: " << kCowVersionMinor;
        return false;
    }

    return ParseOps(fd, label);
}

bool CowParserV2::ParseOps(borrowed_fd fd, std::optional<uint64_t> label) {
    uint64_t pos;
    auto xor_data_loc = std::make_shared<std::unordered_map<uint64_t, uint64_t>>();

    // Skip the scratch space
    if (header_.prefix.major_version >= 2 && (header_.buffer_size > 0)) {
        LOG(DEBUG) << " Scratch space found of size: " << header_.buffer_size;
        size_t init_offset = header_.prefix.header_size + header_.buffer_size;
        pos = lseek(fd.get(), init_offset, SEEK_SET);
        if (pos != init_offset) {
            PLOG(ERROR) << "lseek ops failed";
            return false;
        }
    } else {
        pos = lseek(fd.get(), header_.prefix.header_size, SEEK_SET);
        if (pos != header_.prefix.header_size) {
            PLOG(ERROR) << "lseek ops failed";
            return false;
        }
        // Reading a v1 version of COW which doesn't have buffer_size.
        header_.buffer_size = 0;
    }
    uint64_t data_pos = 0;

    if (header_.cluster_ops) {
        data_pos = pos + header_.cluster_ops * sizeof(CowOperationV2);
    } else {
        data_pos = pos + sizeof(CowOperationV2);
    }

    auto ops_buffer = std::make_shared<std::vector<CowOperationV2>>();
    uint64_t current_op_num = 0;
    uint64_t cluster_ops = header_.cluster_ops ?: 1;
    bool done = false;

    // Alternating op clusters and data
    while (!done) {
        uint64_t to_add = std::min(cluster_ops, (fd_size_ - pos) / sizeof(CowOperationV2));
        if (to_add == 0) break;
        ops_buffer->resize(current_op_num + to_add);
        if (!android::base::ReadFully(fd, &ops_buffer->data()[current_op_num],
                                      to_add * sizeof(CowOperationV2))) {
            PLOG(ERROR) << "read op failed";
            return false;
        }
        // Parse current cluster to find start of next cluster
        while (current_op_num < ops_buffer->size()) {
            auto& current_op = ops_buffer->data()[current_op_num];
            current_op_num++;
            if (current_op.type == kCowXorOp) {
                xor_data_loc->insert({current_op.new_block, data_pos});
            }
            pos += sizeof(CowOperationV2) + GetNextOpOffset(current_op, header_.cluster_ops);
            data_pos += current_op.data_length + GetNextDataOffset(current_op, header_.cluster_ops);

            if (current_op.type == kCowClusterOp) {
                break;
            } else if (current_op.type == kCowLabelOp) {
                last_label_ = {current_op.source};

                // If we reach the requested label, stop reading.
                if (label && label.value() == current_op.source) {
                    done = true;
                    break;
                }
            } else if (current_op.type == kCowFooterOp) {
                footer_.emplace();
                CowFooter* footer = &footer_.value();
                memcpy(&footer_->op, &current_op, sizeof(footer->op));
                off_t offs = lseek(fd.get(), pos, SEEK_SET);
                if (offs < 0 || pos != static_cast<uint64_t>(offs)) {
                    PLOG(ERROR) << "lseek next op failed " << offs;
                    return false;
                }
                if (!android::base::ReadFully(fd, &footer->unused, sizeof(footer->unused))) {
                    LOG(ERROR) << "Could not read COW footer";
                    return false;
                }

                // Drop the footer from the op stream.
                current_op_num--;
                done = true;
                break;
            }
        }

        // Position for next cluster read
        off_t offs = lseek(fd.get(), pos, SEEK_SET);
        if (offs < 0 || pos != static_cast<uint64_t>(offs)) {
            PLOG(ERROR) << "lseek next op failed " << offs;
            return false;
        }
        ops_buffer->resize(current_op_num);
    }

    LOG(DEBUG) << "COW file read complete. Total ops: " << ops_buffer->size();
    // To successfully parse a COW file, we need either:
    //  (1) a label to read up to, and for that label to be found, or
    //  (2) a valid footer.
    if (label) {
        if (!last_label_) {
            LOG(ERROR) << "Did not find label " << label.value()
                       << " while reading COW (no labels found)";
            return false;
        }
        if (last_label_.value() != label.value()) {
            LOG(ERROR) << "Did not find label " << label.value()
                       << ", last label=" << last_label_.value();
            return false;
        }
    } else if (!footer_) {
        LOG(ERROR) << "No COW footer found";
        return false;
    }

    uint8_t csum[32];
    memset(csum, 0, sizeof(uint8_t) * 32);

    if (footer_) {
        if (ops_buffer->size() != footer_->op.num_ops) {
            LOG(ERROR) << "num ops does not match, expected " << footer_->op.num_ops << ", found "
                       << ops_buffer->size();
            return false;
        }
        if (ops_buffer->size() * sizeof(CowOperationV2) != footer_->op.ops_size) {
            LOG(ERROR) << "ops size does not match ";
            return false;
        }
    }

    v2_ops_ = ops_buffer;
    v2_ops_->shrink_to_fit();
    xor_data_loc_ = xor_data_loc;
    return true;
}

bool CowParserV2::Translate(TranslatedCowOps* out) {
    out->ops = std::make_shared<std::vector<CowOperationV3>>(v2_ops_->size());

    // Translate the operation buffer from on disk to in memory
    for (size_t i = 0; i < out->ops->size(); i++) {
        const auto& v2_op = v2_ops_->at(i);

        auto& new_op = out->ops->at(i);
        new_op.set_type(v2_op.type);
        new_op.data_length = v2_op.data_length;

        if (v2_op.new_block > std::numeric_limits<uint32_t>::max()) {
            LOG(ERROR) << "Out-of-range new block in COW op: " << v2_op;
            return false;
        }
        new_op.new_block = v2_op.new_block;

        uint64_t source_info = v2_op.source;
        if (new_op.type() != kCowLabelOp) {
            source_info &= kCowOpSourceInfoDataMask;
            if (source_info != v2_op.source) {
                LOG(ERROR) << "Out-of-range source value in COW op: " << v2_op;
                return false;
            }
        }
        if (v2_op.compression != kCowCompressNone) {
            if (header_.compression_algorithm == kCowCompressNone) {
                header_.compression_algorithm = v2_op.compression;
            } else if (header_.compression_algorithm != v2_op.compression) {
                LOG(ERROR) << "COW has mixed compression types which is not supported;"
                           << " previously saw " << header_.compression_algorithm << ", got "
                           << v2_op.compression << ", op: " << v2_op;
                return false;
            }
        }
        new_op.set_source(source_info);
    }

    out->header = header_;
    return true;
}

}  // namespace snapshot
}  // namespace android
