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

#include "test_partition_opener.h"

#include <errno.h>

namespace android {
namespace fs_mgr {

using android::base::unique_fd;

TestPartitionOpener::TestPartitionOpener(
        const std::map<std::string, int>& partition_map,
        const std::map<std::string, BlockDeviceInfo>& partition_info)
    : partition_map_(partition_map), partition_info_(partition_info) {}

unique_fd TestPartitionOpener::Open(const std::string& partition_name, int flags) const {
    auto iter = partition_map_.find(partition_name);
    if (iter == partition_map_.end()) {
        errno = ENOENT;
        return {};
    }
    return unique_fd{dup(iter->second)};
}

bool TestPartitionOpener::GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const {
    auto iter = partition_info_.find(partition_name);
    if (iter == partition_info_.end()) {
        errno = ENOENT;
        return false;
    }
    *info = iter->second;
    return true;
}

}  // namespace fs_mgr
}  // namespace android
