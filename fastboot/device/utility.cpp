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

#include "utility.h"

#include <android-base/logging.h>

#include "fastboot_device.h"

using android::base::unique_fd;
using android::hardware::boot::V1_0::Slot;

static bool OpenPhysicalPartition(const std::string& name, PartitionHandle* handle) {
    std::optional<std::string> path = FindPhysicalPartition(name);
    if (!path) {
        return false;
    }
    *handle = PartitionHandle(*path);
    return true;
}

bool OpenPartition(FastbootDevice* /* device */, const std::string& name, PartitionHandle* handle) {
    if (!OpenPhysicalPartition(name, handle)) {
        LOG(ERROR) << "No such partition: " << name;
        return false;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(handle->path().c_str(), O_WRONLY | O_EXCL)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to open block device: " << handle->path();
        return false;
    }
    handle->set_fd(std::move(fd));
    return true;
}

std::optional<std::string> FindPhysicalPartition(const std::string& name) {
    std::string path = "/dev/block/by-name/" + name;
    if (access(path.c_str(), R_OK | W_OK) < 0) {
        return {};
    }
    return path;
}

bool GetSlotNumber(const std::string& slot, Slot* number) {
    if (slot.size() != 1) {
        return false;
    }
    if (slot[0] < 'a' || slot[0] > 'z') {
        return false;
    }
    *number = slot[0] - 'a';
    return true;
}
