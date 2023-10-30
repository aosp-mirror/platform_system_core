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

constexpr char kOverlayfsFileContext[] = "u:object_r:overlayfs_file:s0";

constexpr char kScratchMountPoint[] = "/mnt/scratch";
constexpr char kOverlayTopDir[] = "overlay";
constexpr char kUpperName[] = "upper";
constexpr char kWorkName[] = "work";

#if ALLOW_ADBD_DISABLE_VERITY
constexpr bool kAllowOverlayfs = true;
#else
constexpr bool kAllowOverlayfs = false;
#endif

class AutoSetFsCreateCon final {
  public:
    AutoSetFsCreateCon() {}
    AutoSetFsCreateCon(const std::string& context) { Set(context); }
    ~AutoSetFsCreateCon() { Restore(); }

    bool Ok() const { return ok_; }
    bool Set(const std::string& context);
    bool Restore();

  private:
    bool ok_ = false;
    bool restored_ = false;
};

bool fs_mgr_is_dsu_running();
bool fs_mgr_filesystem_has_space(const std::string& mount_point);
const std::string fs_mgr_mount_point(const std::string& mount_point);
bool OverlayfsSetupAllowed(bool verbose = false);
bool MountScratch(const std::string& device_path, bool readonly = false);
bool fs_mgr_overlayfs_umount_scratch();
std::vector<const std::string> OverlayMountPoints();
bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point, bool overlay_only = true);
bool fs_mgr_wants_overlayfs(android::fs_mgr::FstabEntry* entry);
android::fs_mgr::Fstab fs_mgr_overlayfs_candidate_list(const android::fs_mgr::Fstab& fstab);
std::string GetEncodedBaseDirForMountPoint(const std::string& mount_point);
