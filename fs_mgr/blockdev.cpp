/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include <dirent.h>
#include <libdm/dm.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include "blockdev.h"

using android::base::Basename;
using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::dm::DeviceMapper;

// Return the parent device of a partition. Converts e.g. "sda26" into "sda".
static std::string PartitionParent(const std::string& blockdev) {
    if (blockdev.find('/') != std::string::npos) {
        LOG(ERROR) << __func__ << ": invalid argument " << blockdev;
        return blockdev;
    }
    auto dir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/sys/class/block"), closedir};
    if (!dir) {
        return blockdev;
    }
    for (struct dirent* ent = readdir(dir.get()); ent; ent = readdir(dir.get())) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        std::string path = StringPrintf("/sys/class/block/%s/%s", ent->d_name, blockdev.c_str());
        struct stat statbuf;
        if (stat(path.c_str(), &statbuf) >= 0) {
            return ent->d_name;
        }
    }
    return blockdev;
}

// Convert a major:minor pair into a block device name.
static std::string BlockdevName(dev_t dev) {
    auto dir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/dev/block"), closedir};
    if (!dir) {
        return {};
    }
    for (struct dirent* ent = readdir(dir.get()); ent; ent = readdir(dir.get())) {
        if (ent->d_name[0] == '.') {
            continue;
        }
        const std::string path = std::string("/dev/block/") + ent->d_name;
        struct stat statbuf;
        if (stat(path.c_str(), &statbuf) >= 0 && dev == statbuf.st_rdev) {
            return ent->d_name;
        }
    }
    return {};
}

// Trim whitespace from the end of a string.
static void rtrim(std::string& s) {
    s.erase(s.find_last_not_of('\n') + 1, s.length());
}

// For file `file_path`, retrieve the block device backing the filesystem on
// which the file exists and return the queue depth of the block device.
static Result<uint32_t> BlockDeviceQueueDepth(const std::string& file_path) {
    struct stat statbuf;
    int res = stat(file_path.c_str(), &statbuf);
    if (res < 0) {
        return ErrnoError() << "stat(" << file_path << ")";
    }
    std::string blockdev = "/dev/block/" + BlockdevName(statbuf.st_dev);
    LOG(DEBUG) << __func__ << ": " << file_path << " -> " << blockdev;
    if (blockdev.empty()) {
        return Errorf("Failed to convert {}:{} (path {})", major(statbuf.st_dev),
                      minor(statbuf.st_dev), file_path.c_str());
    }
    auto& dm = DeviceMapper::Instance();
    for (;;) {
        std::optional<std::string> child = dm.GetParentBlockDeviceByPath(blockdev);
        if (!child) {
            break;
        }
        LOG(DEBUG) << __func__ << ": " << blockdev << " -> " << *child;
        blockdev = *child;
    }
    std::optional<std::string> maybe_blockdev = android::dm::ExtractBlockDeviceName(blockdev);
    if (!maybe_blockdev) {
        return Errorf("Failed to remove /dev/block/ prefix from {}", blockdev);
    }
    blockdev = PartitionParent(*maybe_blockdev);
    LOG(DEBUG) << __func__ << ": "
               << "Partition parent: " << blockdev;
    const std::string nr_tags_path =
            StringPrintf("/sys/class/block/%s/mq/0/nr_tags", blockdev.c_str());
    std::string nr_tags;
    if (!android::base::ReadFileToString(nr_tags_path, &nr_tags)) {
        return Errorf("Failed to read {}", nr_tags_path);
    }
    rtrim(nr_tags);
    LOG(DEBUG) << __func__ << ": " << file_path << " is backed by /dev/" << blockdev
               << " and that block device supports queue depth " << nr_tags;
    return strtol(nr_tags.c_str(), NULL, 0);
}

// Set 'nr_requests' of `loop_device_path` to the queue depth of the block
// device backing `file_path`.
Result<void> ConfigureQueueDepth(const std::string& loop_device_path,
                                 const std::string& file_path) {
    if (!StartsWith(loop_device_path, "/dev/")) {
        return Error() << "Invalid argument " << loop_device_path;
    }

    const std::string loop_device_name = Basename(loop_device_path);

    const auto qd = BlockDeviceQueueDepth(file_path);
    if (!qd.ok()) {
        return qd.error();
    }
    const std::string nr_requests = StringPrintf("%u", *qd);
    const std::string sysfs_path =
            StringPrintf("/sys/class/block/%s/queue/nr_requests", loop_device_name.c_str());
    unique_fd sysfs_fd(open(sysfs_path.c_str(), O_RDWR | O_CLOEXEC));
    if (sysfs_fd == -1) {
        return ErrnoError() << "Failed to open " << sysfs_path;
    }

    const int res = write(sysfs_fd.get(), nr_requests.data(), nr_requests.length());
    if (res < 0) {
        return ErrnoError() << "Failed to write to " << sysfs_path;
    }
    return {};
}
