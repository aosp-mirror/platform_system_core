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

#include "android-base/file.h"
#include "fs_mgr/roots.h"

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

#include "fs_mgr.h"
#include "fs_mgr_dm_linear.h"
#include "fs_mgr_priv.h"

namespace android {
namespace fs_mgr {

static constexpr const char* kSystemRoot = "/system";

static bool gDidMapLogicalPartitions = false;

FstabEntry* GetEntryForPath(Fstab* fstab, const std::string& path) {
    if (path.empty()) return nullptr;
    std::string str(path);
    while (true) {
        auto entry = GetEntryForMountPoint(fstab, str);
        if (entry != nullptr) return entry;
        str = android::base::Dirname(str);
        if (!str.compare(".") || !str.compare("/")) break;
    }
    return nullptr;
}

std::vector<FstabEntry*> GetEntriesForPath(Fstab* fstab, const std::string& path) {
    std::vector<FstabEntry*> entries;
    if (path.empty()) return entries;

    std::string str(path);
    while (true) {
        entries = GetEntriesForMountPoint(fstab, str);
        if (!entries.empty()) return entries;
        str = android::base::Dirname(str);
        if (!str.compare(".") || !str.compare("/")) break;
    }
    return entries;
}

enum class MountState {
    ERROR = -1,
    NOT_MOUNTED = 0,
    MOUNTED = 1,
};

static MountState GetMountState(const std::string& mount_point) {
    Fstab mounted_fstab;
    if (!ReadFstabFromFile("/proc/mounts", &mounted_fstab)) {
        LERROR << "Failed to scan mounted volumes";
        return MountState::ERROR;
    }

    auto mv = GetEntryForMountPoint(&mounted_fstab, mount_point);
    if (mv != nullptr) {
        return MountState::MOUNTED;
    }
    return MountState::NOT_MOUNTED;
}

bool TryPathMount(FstabEntry* rec, const std::string& mount_pt) {
    if (rec->fs_type == "ramdisk") {
        // The ramdisk is always mounted.
        return true;
    }

    // If we can't acquire the block device for a logical partition, it likely
    // was never created. In that case we try to create it.
    if (rec->fs_mgr_flags.logical && !fs_mgr_update_logical_partition(rec)) {
        if (gDidMapLogicalPartitions) {
            LERROR << "Failed to find block device for partition";
            return false;
        }
        std::string super_name = fs_mgr_get_super_partition_name();
        if (!android::fs_mgr::CreateLogicalPartitions("/dev/block/by-name/" + super_name)) {
            LERROR << "Failed to create logical partitions";
            return false;
        }
        gDidMapLogicalPartitions = true;
        if (!fs_mgr_update_logical_partition(rec)) {
            LERROR << "Failed to find block device for partition";
            return false;
        }
    }

    const std::string mount_point = mount_pt.empty() ? rec->mount_point : mount_pt;

    auto mounted = GetMountState(mount_point);
    if (mounted == MountState::ERROR) {
        return false;
    }
    if (mounted == MountState::MOUNTED) {
        return true;
    }

    static const std::vector<std::string> supported_fs{"ext4", "squashfs", "vfat", "exfat", "f2fs",
                                                       "erofs", "none"};
    if (std::find(supported_fs.begin(), supported_fs.end(), rec->fs_type) == supported_fs.end()) {
        LERROR << "unknown fs_type \"" << rec->fs_type << "\" for " << mount_point;
        return false;
    }

    int result = fs_mgr_do_mount_one(*rec, mount_point);
    if (result == -1 && rec->fs_mgr_flags.formattable) {
        PERROR << "Failed to mount " << mount_point << "; formatting";
        if (fs_mgr_do_format(*rec) != 0) {
            PERROR << "Failed to format " << mount_point;
            return false;
        }
        result = fs_mgr_do_mount_one(*rec, mount_point);
    }

    if (result == -1) {
        PERROR << "Failed to mount " << mount_point;
        return false;
    }
    return true;
}

bool EnsurePathMounted(Fstab* fstab, const std::string& path, const std::string& mount_point) {
    auto entries = GetEntriesForPath(fstab, path);
    if (entries.empty()) {
        LERROR << "unknown volume for path [" << path << "]";
        return false;
    }

    for (auto entry : entries) {
        if (TryPathMount(entry, mount_point)) return true;
    }

    LERROR << "Failed to mount for path [" << path << "]";
    return false;
}

bool EnsurePathUnmounted(Fstab* fstab, const std::string& path) {
    auto rec = GetEntryForPath(fstab, path);
    if (rec == nullptr) {
        LERROR << "unknown volume for path [" << path << "]";
        return false;
    }
    if (rec->fs_type == "ramdisk") {
        // The ramdisk is always mounted; you can't unmount it.
        return false;
    }

    Fstab mounted_fstab;
    if (!ReadFstabFromFile("/proc/mounts", &mounted_fstab)) {
        LERROR << "Failed to scan mounted volumes";
        return false;
    }

    auto mounted = GetMountState(rec->mount_point);
    if (mounted == MountState::ERROR) {
        return false;
    }
    if (mounted == MountState::NOT_MOUNTED) {
        return true;
    }

    int result = umount(rec->mount_point.c_str());
    if (result == -1) {
        PWARNING << "Failed to umount " << rec->mount_point;
        return false;
    }
    return true;
}

std::string GetSystemRoot() {
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        LERROR << "Failed to read default fstab";
        return "";
    }

    auto entry = GetEntryForMountPoint(&fstab, kSystemRoot);
    if (entry == nullptr) {
        return "/";
    }

    return kSystemRoot;
}

bool LogicalPartitionsMapped() {
    return gDidMapLogicalPartitions;
}

}  // namespace fs_mgr
}  // namespace android
