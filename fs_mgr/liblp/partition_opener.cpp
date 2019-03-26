/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "liblp/partition_opener.h"

#if defined(__linux__)
#include <linux/fs.h>
#endif
#if !defined(_WIN32)
#include <sys/ioctl.h>
#endif
#include <sys/types.h>
#include <unistd.h>

#include <android-base/file.h>

#include "utility.h"

namespace android {
namespace fs_mgr {

using android::base::unique_fd;

namespace {

std::string GetPartitionAbsolutePath(const std::string& path) {
    if (path[0] == '/') {
        return path;
    }
    return "/dev/block/by-name/" + path;
}

bool GetBlockDeviceInfo(const std::string& block_device, BlockDeviceInfo* device_info) {
#if defined(__linux__)
    unique_fd fd = GetControlFileOrOpen(block_device.c_str(), O_RDONLY);
    if (fd < 0) {
        PERROR << __PRETTY_FUNCTION__ << "open '" << block_device << "' failed";
        return false;
    }
    if (!GetDescriptorSize(fd, &device_info->size)) {
        return false;
    }
    if (ioctl(fd, BLKIOMIN, &device_info->alignment) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKIOMIN failed on " << block_device;
        return false;
    }

    int alignment_offset;
    if (ioctl(fd, BLKALIGNOFF, &alignment_offset) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKALIGNOFF failed on " << block_device;
        return false;
    }
    int logical_block_size;
    if (ioctl(fd, BLKSSZGET, &logical_block_size) < 0) {
        PERROR << __PRETTY_FUNCTION__ << "BLKSSZGET failed on " << block_device;
        return false;
    }

    device_info->alignment_offset = static_cast<uint32_t>(alignment_offset);
    device_info->logical_block_size = static_cast<uint32_t>(logical_block_size);
    device_info->partition_name = android::base::Basename(block_device);
    return true;
#else
    (void)block_device;
    (void)device_info;
    LERROR << __PRETTY_FUNCTION__ << ": Not supported on this operating system.";
    return false;
#endif
}

}  // namespace

unique_fd PartitionOpener::Open(const std::string& partition_name, int flags) const {
    std::string path = GetPartitionAbsolutePath(partition_name);
    return GetControlFileOrOpen(path.c_str(), flags | O_CLOEXEC);
}

bool PartitionOpener::GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const {
    std::string path = GetPartitionAbsolutePath(partition_name);
    return GetBlockDeviceInfo(path, info);
}

}  // namespace fs_mgr
}  // namespace android
