// Copyright (C) 2020 The Android Open Source Project
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

#include <libsnapshot/snapshot.h>

#include <gmock/gmock.h>

namespace android::snapshot {

class MockDeviceInfo : public SnapshotManager::IDeviceInfo {
  public:
    MOCK_METHOD(std::string, GetMetadataDir, (), (const, override));
    MOCK_METHOD(std::string, GetSlotSuffix, (), (const, override));
    MOCK_METHOD(std::string, GetOtherSlotSuffix, (), (const, override));
    MOCK_METHOD(std::string, GetSuperDevice, (uint32_t slot), (const, override));
    MOCK_METHOD(const android::fs_mgr::IPartitionOpener&, GetPartitionOpener, (), (const));
    MOCK_METHOD(bool, IsOverlayfsSetup, (), (const, override));
    MOCK_METHOD(bool, SetBootControlMergeStatus, (MergeStatus status), (override));
    MOCK_METHOD(bool, SetSlotAsUnbootable, (unsigned int slot), (override));
    MOCK_METHOD(bool, IsRecovery, (), (const, override));
    MOCK_METHOD(bool, IsFirstStageInit, (), (const, override));
    MOCK_METHOD(std::unique_ptr<android::fiemap::IImageManager>, OpenImageManager, (),
                (const, override));
};

}  // namespace android::snapshot
