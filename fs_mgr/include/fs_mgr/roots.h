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

#include <string>

#include <fs_mgr.h>

namespace android {
namespace fs_mgr {

// Finds the volume specified by the given path. fs_mgr_get_entry_for_mount_point() does exact match
// only, so it attempts the prefixes recursively (e.g. "/cache/recovery/last_log",
// "/cache/recovery", "/cache", "/" for a given path of "/cache/recovery/last_log") and returns the
// first match or nullptr.
FstabEntry* GetEntryForPath(Fstab* fstab, const std::string& path);

// Make sure that the volume 'path' is on is mounted.
// * If 'mount_point' is nullptr, use mount point in fstab. Caller can call
//   fs_mgr_ensure_path_unmounted() with the same 'path' argument to unmount.
// * If 'mount_point' is not nullptr, the mount point is overridden. Caller can
//   call umount(mount_point) to unmount.
// Returns true on success (volume is mounted).
bool EnsurePathMounted(Fstab* fstab, const std::string& path, const std::string& mount_point = "");

// Make sure that the volume 'path' is on is unmounted.  Returns true on
// success (volume is unmounted).
bool EnsurePathUnmounted(Fstab* fstab, const std::string& path);

// Return "/system" if it is in default fstab, otherwise "/".
std::string GetSystemRoot();

// Return true iff logical partitions are mapped when partitions are mounted via ensure_path_mounted
// functions.
bool LogicalPartitionsMapped();

}  // namespace fs_mgr
}  // namespace android
