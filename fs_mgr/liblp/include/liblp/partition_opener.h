//
// Copyright (C) 2018 The Android Open Source Project
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

#pragma once

#include <stdint.h>

#include <string>

#include <android-base/unique_fd.h>

namespace android {
namespace fs_mgr {

struct BlockDeviceInfo {
    BlockDeviceInfo() : size(0), alignment(0), alignment_offset(0), logical_block_size(0) {}
    BlockDeviceInfo(const std::string& partition_name, uint64_t size, uint32_t alignment,
                    uint32_t alignment_offset, uint32_t logical_block_size)
        : size(size),
          alignment(alignment),
          alignment_offset(alignment_offset),
          logical_block_size(logical_block_size),
          partition_name(partition_name) {}
    // Size of the block device, in bytes.
    uint64_t size;
    // Optimal target alignment, in bytes. Partition extents will be aligned to
    // this value by default. This value must be 0 or a multiple of 512.
    uint32_t alignment;
    // Alignment offset to parent device (if any), in bytes. The sector at
    // |alignment_offset| on the target device is correctly aligned on its
    // parent device. This value must be 0 or a multiple of 512.
    uint32_t alignment_offset;
    // Block size, for aligning extent sizes and partition sizes.
    uint32_t logical_block_size;
    // The physical partition name for this block device, as it would appear in
    // the GPT or under /dev/block/by-name.
    std::string partition_name;
};

// Test-friendly interface for interacting with partitions.
class IPartitionOpener {
  public:
    virtual ~IPartitionOpener() = default;

    // Open the given named physical partition with the provided open() flags.
    // The name can be an absolute path if the full path is already known.
    virtual android::base::unique_fd Open(const std::string& partition_name, int flags) const = 0;

    // Return block device information about the given named physical partition.
    // The name can be an absolute path if the full path is already known.
    virtual bool GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const = 0;
};

// Helper class to implement IPartitionOpener. If |partition_name| is not an
// absolute path, /dev/block/by-name/ will be prepended.
class PartitionOpener : public IPartitionOpener {
  public:
    virtual android::base::unique_fd Open(const std::string& partition_name,
                                          int flags) const override;
    virtual bool GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const override;
};

}  // namespace fs_mgr
}  // namespace android
