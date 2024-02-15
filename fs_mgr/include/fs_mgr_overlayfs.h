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

#include <functional>
#include <set>
#include <string>

#include <fstab/fstab.h>

// Keep the list short and only add interfaces that must be exported public.

bool fs_mgr_overlayfs_mount_all(android::fs_mgr::Fstab* fstab);
bool fs_mgr_overlayfs_is_setup();

namespace android {
namespace fs_mgr {

// Mount the overlayfs override for |fstab_entry|.
void MountOverlayfs(const FstabEntry& fstab_entry, bool* scratch_can_be_mounted);

void MapScratchPartitionIfNeeded(Fstab* fstab,
                                 const std::function<bool(const std::set<std::string>&)>& init);

// Teardown overlays of all sources (cache dir, scratch device, DSU) for |mount_point|.
// Teardown all overlays if |mount_point| is empty.
//
// Note: This should be called if and only if in recovery or fastbootd to teardown
// overlays if any partition is flashed or updated.
void TeardownAllOverlayForMountPoint(const std::string& mount_point = {});

}  // namespace fs_mgr
}  // namespace android
