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

#include <libsnapshot/snapshot.h>

namespace android {
namespace snapshot {

std::unique_ptr<SnapshotManager> SnapshotManager::New() {
    return std::make_unique<SnapshotManager>();
}

bool SnapshotManager::CreateSnapshot(const std::string& name, const std::string& base_device,
                                     uint64_t cow_size, std::string* dev_path,
                                     const std::chrono::milliseconds& timeout_ms) {
    // (1) Create COW device using libgsi_image.
    // (2) Create snapshot device using libdm + DmTargetSnapshot.
    // (3) Record partition in /metadata/ota.
    (void)name;
    (void)base_device;
    (void)cow_size;
    (void)dev_path;
    (void)timeout_ms;
    return false;
}

bool SnapshotManager::MapSnapshotDevice(const std::string& name, const std::string& base_device,
                                        const std::chrono::milliseconds& timeout_ms,
                                        std::string* dev_path) {
    (void)name;
    (void)base_device;
    (void)dev_path;
    (void)timeout_ms;
    return false;
}

bool SnapshotManager::UnmapSnapshotDevice(const std::string& name) {
    (void)name;
    return false;
}

bool SnapshotManager::DeleteSnapshot(const std::string& name) {
    (void)name;
    return false;
}

bool SnapshotManager::InitiateMerge() {
    return false;
}

bool SnapshotManager::WaitForMerge() {
    return false;
}

UpdateStatus SnapshotManager::GetUpdateStatus(double* progress) {
    *progress = 0.0f;
    return UpdateStatus::None;
}

}  // namespace snapshot
}  // namespace android
