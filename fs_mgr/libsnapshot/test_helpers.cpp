// Copyright (C) 2019 The Android Open Source Project
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

#include "test_helpers.h"

#include <gtest/gtest.h>

namespace android {
namespace snapshot {

using android::fiemap::IImageManager;

void DeleteBackingImage(IImageManager* manager, const std::string& name) {
    if (manager->IsImageMapped(name)) {
        ASSERT_TRUE(manager->UnmapImageDevice(name));
    }
    if (manager->BackingImageExists(name)) {
        ASSERT_TRUE(manager->DeleteBackingImage(name));
    }
}

android::base::unique_fd TestPartitionOpener::Open(const std::string& partition_name,
                                                   int flags) const {
    if (partition_name == "super") {
        return PartitionOpener::Open(fake_super_path_, flags);
    }
    return PartitionOpener::Open(partition_name, flags);
}

bool TestPartitionOpener::GetInfo(const std::string& partition_name,
                                  android::fs_mgr::BlockDeviceInfo* info) const {
    if (partition_name == "super") {
        return PartitionOpener::GetInfo(fake_super_path_, info);
    }
    return PartitionOpener::GetInfo(partition_name, info);
}

}  // namespace snapshot
}  // namespace android
