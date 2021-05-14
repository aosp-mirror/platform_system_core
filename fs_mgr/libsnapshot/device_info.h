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

#ifdef LIBSNAPSHOT_USE_HAL
#include <android/hardware/boot/1.1/IBootControl.h>
#endif
#include <liblp/partition_opener.h>
#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

class DeviceInfo final : public SnapshotManager::IDeviceInfo {
    using MergeStatus = android::hardware::boot::V1_1::MergeStatus;

  public:
    std::string GetMetadataDir() const override;
    std::string GetSlotSuffix() const override;
    std::string GetOtherSlotSuffix() const override;
    const android::fs_mgr::IPartitionOpener& GetPartitionOpener() const override;
    std::string GetSuperDevice(uint32_t slot) const override;
    bool IsOverlayfsSetup() const override;
    bool SetBootControlMergeStatus(MergeStatus status) override;
    bool SetSlotAsUnbootable(unsigned int slot) override;
    bool IsRecovery() const override;
    std::unique_ptr<IImageManager> OpenImageManager() const override;
    bool IsFirstStageInit() const override;

    void set_first_stage_init(bool value) { first_stage_init_ = value; }

  private:
    bool EnsureBootHal();

    android::fs_mgr::PartitionOpener opener_;
    bool first_stage_init_ = false;
#ifdef LIBSNAPSHOT_USE_HAL
    android::sp<android::hardware::boot::V1_1::IBootControl> boot_control_;
#endif
};

}  // namespace snapshot
}  // namespace android
