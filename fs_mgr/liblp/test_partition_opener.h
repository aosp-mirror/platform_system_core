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

#pragma once

#include <map>
#include <string>

#include <android-base/unique_fd.h>
#include <liblp/partition_opener.h>

namespace android {
namespace fs_mgr {

class TestPartitionOpener : public PartitionOpener {
  public:
    explicit TestPartitionOpener(const std::map<std::string, int>& partition_map,
                                 const std::map<std::string, BlockDeviceInfo>& partition_info = {});

    android::base::unique_fd Open(const std::string& partition_name, int flags) const override;
    bool GetInfo(const std::string& partition_name, BlockDeviceInfo* info) const override;

  private:
    std::map<std::string, int> partition_map_;
    std::map<std::string, BlockDeviceInfo> partition_info_;
};

}  // namespace fs_mgr
}  // namespace android
