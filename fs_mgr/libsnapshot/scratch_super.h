// Copyright (C) 2024 The Android Open Source Project
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

namespace android {
namespace snapshot {

constexpr char kMkExt4[] = "/system/bin/mke2fs";
constexpr char kOtaMetadataFileContext[] = "u:object_r:ota_metadata_file:s0";
constexpr char kOtaMetadataMount[] = "/mnt/scratch_ota_metadata_super";
const size_t kOtaMetadataPartitionSize = uint64_t(1 * 1024 * 1024);
constexpr char kPhysicalDevice[] = "/dev/block/by-name/";

bool IsScratchOtaMetadataOnSuper();
std::string GetScratchOtaMetadataPartition();
std::string MapScratchOtaMetadataPartition(const std::string& device);
bool CreateScratchOtaMetadataOnSuper(const ISnapshotManager::IDeviceInfo* info = nullptr);
bool CleanupScratchOtaMetadataIfPresent(const ISnapshotManager::IDeviceInfo* info = nullptr);

}  // namespace snapshot
}  // namespace android
