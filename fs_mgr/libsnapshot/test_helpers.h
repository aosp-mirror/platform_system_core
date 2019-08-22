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

#pragma once

#include <string>

#include <libfiemap/image_manager.h>
#include <liblp/partition_opener.h>
#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

using namespace std::string_literals;

class TestDeviceInfo : public SnapshotManager::IDeviceInfo {
  public:
    std::string GetGsidDir() const override { return "ota/test"s; }
    std::string GetMetadataDir() const override { return "/metadata/ota/test"s; }
    std::string GetSlotSuffix() const override { return slot_suffix_; }

    void set_slot_suffix(const std::string& suffix) { slot_suffix_ = suffix; }

  private:
    std::string slot_suffix_ = "_a";
};

// Redirect requests for "super" to our fake super partition.
class TestPartitionOpener final : public android::fs_mgr::PartitionOpener {
  public:
    explicit TestPartitionOpener(const std::string& fake_super_path)
        : fake_super_path_(fake_super_path) {}

    android::base::unique_fd Open(const std::string& partition_name, int flags) const override;
    bool GetInfo(const std::string& partition_name,
                 android::fs_mgr::BlockDeviceInfo* info) const override;

  private:
    std::string fake_super_path_;
};

// Helper for error-spam-free cleanup.
void DeleteBackingImage(android::fiemap::IImageManager* manager, const std::string& name);

}  // namespace snapshot
}  // namespace android
