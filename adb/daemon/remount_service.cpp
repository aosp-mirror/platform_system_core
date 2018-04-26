/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>
#include <vector>

#include <android-base/properties.h>
#include <ext4_utils/ext4_utils.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "fs_mgr.h"

// Returns the device used to mount a directory in /proc/mounts.
static std::string find_proc_mount(const char* dir) {
    std::unique_ptr<FILE, int(*)(FILE*)> fp(setmntent("/proc/mounts", "r"), endmntent);
    if (!fp) {
        return "";
    }

    mntent* e;
    while ((e = getmntent(fp.get())) != nullptr) {
        if (strcmp(dir, e->mnt_dir) == 0) {
            return e->mnt_fsname;
        }
    }
    return "";
}

// Returns the device used to mount a directory in the fstab.
static std::string find_fstab_mount(const char* dir) {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    struct fstab_rec* rec = fs_mgr_get_entry_for_mount_point(fstab.get(), dir);
    return rec ? rec->blk_device : "";
}

// The proc entry for / is full of lies, so check fstab instead.
// /proc/mounts lists rootfs and /dev/root, neither of which is what we want.
static std::string find_mount(const char* dir, bool is_root) {
    if (is_root) {
        return find_fstab_mount(dir);
    } else {
       return find_proc_mount(dir);
    }
}

bool make_block_device_writable(const std::string& dev) {
    int fd = unix_open(dev.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return false;
    }

    int OFF = 0;
    bool result = (ioctl(fd, BLKROSET, &OFF) != -1);
    unix_close(fd);
    return result;
}

static bool fs_has_shared_blocks(const char* dev) {
    struct statfs fs;
    if (statfs(dev, &fs) == -1 || fs.f_type == EXT4_SUPER_MAGIC) {
        return false;
    }
    unique_fd fd(unix_open(dev, O_RDONLY));
    if (fd < 0) {
        return false;
    }
    struct ext4_super_block sb;
    if (lseek64(fd, 1024, SEEK_SET) < 0 || unix_read(fd, &sb, sizeof(sb)) < 0) {
        return false;
    }
    struct fs_info info;
    if (ext4_parse_sb(&sb, &info) < 0) {
        return false;
    }
    return (info.feat_ro_compat & EXT4_FEATURE_RO_COMPAT_SHARED_BLOCKS) != 0;
}

static bool remount_partition(int fd, const char* dir, std::vector<std::string>& dedup) {
    if (!directory_exists(dir)) {
        return true;
    }
    bool is_root = strcmp(dir, "/") == 0;
    std::string dev = find_mount(dir, is_root);
    // Even if the device for the root is not found, we still try to remount it
    // as rw. This typically only happens when running Android in a container:
    // the root will almost always be in a loop device, which is dynamic, so
    // it's not convenient to put in the fstab.
    if (dev.empty() && !is_root) {
        return true;
    }
    if (!dev.empty() && !make_block_device_writable(dev)) {
        WriteFdFmt(fd, "remount of %s failed; couldn't make block device %s writable: %s\n",
                   dir, dev.c_str(), strerror(errno));
        return false;
    }
    if (mount(dev.c_str(), dir, "none", MS_REMOUNT | MS_BIND, nullptr) == -1) {
        // This is useful for cases where the superblock is already marked as
        // read-write, but the mount itself is read-only, such as containers
        // where the remount with just MS_REMOUNT is forbidden by the kernel.
        WriteFdFmt(fd, "remount of the %s mount failed: %s.\n", dir, strerror(errno));
        return false;
    }
    if (mount(dev.c_str(), dir, "none", MS_REMOUNT, nullptr) == -1) {
        if (errno == EROFS && fs_has_shared_blocks(dev.c_str())) {
            // We return true so remount_service() can detect that the only
            // failure was deduplicated filesystems.
            dedup.push_back(dev);
            return true;
        }
        WriteFdFmt(fd, "remount of the %s superblock failed: %s\n", dir, strerror(errno));
        return false;
    }
    return true;
}

void remount_service(int fd, void* cookie) {
    if (getuid() != 0) {
        WriteFdExactly(fd, "Not running as root. Try \"adb root\" first.\n");
        adb_close(fd);
        return;
    }

    bool system_verified = !(android::base::GetProperty("partition.system.verified", "").empty());
    bool vendor_verified = !(android::base::GetProperty("partition.vendor.verified", "").empty());

    if (system_verified || vendor_verified) {
        // Allow remount but warn of likely bad effects
        bool both = system_verified && vendor_verified;
        WriteFdFmt(fd,
                   "dm_verity is enabled on the %s%s%s partition%s.\n",
                   system_verified ? "system" : "",
                   both ? " and " : "",
                   vendor_verified ? "vendor" : "",
                   both ? "s" : "");
        WriteFdExactly(fd,
                       "Use \"adb disable-verity\" to disable verity.\n"
                       "If you do not, remount may succeed, however, you will still "
                       "not be able to write to these volumes.\n");
    }

    bool success = true;
    std::vector<std::string> dedup;
    if (android::base::GetBoolProperty("ro.build.system_root_image", false)) {
        success &= remount_partition(fd, "/", dedup);
    } else {
        success &= remount_partition(fd, "/system", dedup);
    }
    success &= remount_partition(fd, "/odm", dedup);
    success &= remount_partition(fd, "/oem", dedup);
    success &= remount_partition(fd, "/product", dedup);
    success &= remount_partition(fd, "/vendor", dedup);

    if (!success) {
        WriteFdExactly(fd, "remount failed\n");
    } else if (dedup.empty()) {
        WriteFdExactly(fd, "remount succeeded\n");
    } else {
        WriteFdExactly(fd,
                       "The following partitions are deduplicated and could "
                       "not be remounted:\n");
        for (const std::string& name : dedup) {
            WriteFdFmt(fd, "  %s\n", name.c_str());
        }
    }

    adb_close(fd);
}
