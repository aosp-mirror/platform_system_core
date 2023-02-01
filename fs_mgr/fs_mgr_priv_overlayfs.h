/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <string>

#include <fstab/fstab.h>

bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point, bool overlay_only = true);
bool fs_mgr_wants_overlayfs(android::fs_mgr::FstabEntry* entry);
android::fs_mgr::Fstab fs_mgr_overlayfs_candidate_list(const android::fs_mgr::Fstab& fstab);

// If "mount_point" is non-null, set up exactly one overlay.
// If "mount_point" is null, setup any overlays.
//
// If |want_reboot| is non-null, and a reboot is needed to apply overlays, then
// it will be true on return. The caller is responsible for initializing it.
bool fs_mgr_overlayfs_setup(const android::fs_mgr::Fstab& fstab, const char* mount_point = nullptr,
                            bool* want_reboot = nullptr, bool just_disabled_verity = true);

enum class OverlayfsTeardownResult {
    Ok,
    Busy,  // Indicates that overlays are still in use.
    Error
};
OverlayfsTeardownResult fs_mgr_overlayfs_teardown(const char* mount_point = nullptr,
                                                  bool* want_reboot = nullptr);

namespace android {
namespace fs_mgr {

void CleanupOldScratchFiles();

}  // namespace fs_mgr
}  // namespace android
