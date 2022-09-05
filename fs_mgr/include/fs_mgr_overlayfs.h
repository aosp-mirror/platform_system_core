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

#include <fstab/fstab.h>

#include <set>
#include <string>
#include <vector>

android::fs_mgr::Fstab fs_mgr_overlayfs_candidate_list(const android::fs_mgr::Fstab& fstab);

bool fs_mgr_wants_overlayfs(android::fs_mgr::FstabEntry* entry);
bool fs_mgr_overlayfs_mount_all(android::fs_mgr::Fstab* fstab);
bool fs_mgr_overlayfs_teardown(const char* mount_point = nullptr, bool* change = nullptr);
bool fs_mgr_overlayfs_is_setup();
bool fs_mgr_has_shared_blocks(const std::string& mount_point, const std::string& dev);
bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point, bool overlay_only = true);
std::string fs_mgr_get_context(const std::string& mount_point);

// If "mount_point" is non-null, set up exactly one overlay.
// If "mount_point" is null, setup any overlays.
//
// If |want_reboot| is non-null, and a reboot is needed to apply overlays, then
// it will be true on return. The caller is responsible for initializing it.
bool fs_mgr_overlayfs_setup(const char* mount_point = nullptr, bool* want_reboot = nullptr,
                            bool just_disabled_verity = true);

enum class OverlayfsValidResult {
    kNotSupported = 0,
    kOk,
    kOverrideCredsRequired,
};
OverlayfsValidResult fs_mgr_overlayfs_valid();

namespace android {
namespace fs_mgr {

void MapScratchPartitionIfNeeded(Fstab* fstab,
                                 const std::function<bool(const std::set<std::string>&)>& init);
void CleanupOldScratchFiles();

// Teardown overlays of all sources (cache dir, scratch device, DSU) for |mount_point|.
// Teardown all overlays if |mount_point| is empty.
//
// Note: This should be called if and only if in recovery or fastbootd to teardown
// overlays if any partition is flashed or updated.
void TeardownAllOverlayForMountPoint(const std::string& mount_point = {});

}  // namespace fs_mgr
}  // namespace android
