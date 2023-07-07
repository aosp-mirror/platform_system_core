//
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
//

#include "super_flash_helper.h"

#include <android-base/logging.h>

#include "util.h"

using android::base::borrowed_fd;
using android::base::unique_fd;
using android::fs_mgr::SuperImageExtent;

SuperFlashHelper::SuperFlashHelper(const ImageSource& source) : source_(source) {}

bool SuperFlashHelper::Open(borrowed_fd fd) {
    if (!builder_.Open(fd)) {
        LOG(VERBOSE) << "device does not support optimized super flashing";
        return false;
    }

    base_metadata_ = builder_.Export();
    return !!base_metadata_;
}

bool SuperFlashHelper::IncludeInSuper(const std::string& partition) {
    return should_flash_in_userspace(*base_metadata_.get(), partition);
}

bool SuperFlashHelper::AddPartition(const std::string& partition, const std::string& image_name,
                                    bool optional) {
    if (!IncludeInSuper(partition)) {
        return true;
    }
    auto iter = image_fds_.find(image_name);
    if (iter == image_fds_.end()) {
        unique_fd fd = source_.OpenFile(image_name);
        if (fd < 0) {
            if (!optional) {
                LOG(VERBOSE) << "could not find partition image: " << image_name;
                return false;
            }
            return true;
        }
        if (is_sparse_file(fd)) {
            LOG(VERBOSE) << "cannot optimize dynamic partitions with sparse images";
            return false;
        }
        iter = image_fds_.emplace(image_name, std::move(fd)).first;
    }

    if (!builder_.AddPartition(partition, image_name, get_file_size(iter->second))) {
        return false;
    }

    will_flash_.emplace(partition);
    return true;
}

SparsePtr SuperFlashHelper::GetSparseLayout() {
    // Cache extents since the sparse ptr depends on data pointers.
    if (extents_.empty()) {
        extents_ = builder_.GetImageLayout();
        if (extents_.empty()) {
            LOG(VERBOSE) << "device does not support optimized super flashing";
            return {nullptr, nullptr};
        }
    }

    unsigned int block_size = base_metadata_->geometry.logical_block_size;
    int64_t flashed_size = extents_.back().offset + extents_.back().size;
    SparsePtr s(sparse_file_new(block_size, flashed_size), sparse_file_destroy);

    for (const auto& extent : extents_) {
        if (extent.offset / block_size > UINT_MAX) {
            // Super image is too big to send via sparse files (>8TB).
            LOG(VERBOSE) << "super image is too big to flash";
            return {nullptr, nullptr};
        }
        unsigned int block = extent.offset / block_size;

        int rv = 0;
        switch (extent.type) {
            case SuperImageExtent::Type::DONTCARE:
                break;
            case SuperImageExtent::Type::ZERO:
                rv = sparse_file_add_fill(s.get(), 0, extent.size, block);
                break;
            case SuperImageExtent::Type::DATA:
                rv = sparse_file_add_data(s.get(), extent.blob->data(), extent.size, block);
                break;
            case SuperImageExtent::Type::PARTITION: {
                auto iter = image_fds_.find(extent.image_name);
                if (iter == image_fds_.end()) {
                    LOG(FATAL) << "image added but not found: " << extent.image_name;
                    return {nullptr, nullptr};
                }
                rv = sparse_file_add_fd(s.get(), iter->second.get(), extent.image_offset,
                                        extent.size, block);
                break;
            }
            default:
                LOG(VERBOSE) << "unrecognized extent type in super image layout";
                return {nullptr, nullptr};
        }
        if (rv) {
            LOG(VERBOSE) << "sparse failure building super image layout";
            return {nullptr, nullptr};
        }
    }
    return s;
}
