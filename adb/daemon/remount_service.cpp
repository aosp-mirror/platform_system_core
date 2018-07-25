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
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <set>
#include <string>
#include <vector>

#include <android-base/properties.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <ext4_utils/ext4_utils.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "fs_mgr.h"
#include "set_verity_enable_state_service.h"

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

static bool can_unshare_blocks(int fd, const char* dev) {
    const char* E2FSCK_BIN = "/system/bin/e2fsck";
    if (access(E2FSCK_BIN, X_OK)) {
        WriteFdFmt(fd, "e2fsck is not available, cannot undo deduplication on %s\n", dev);
        return false;
    }

    pid_t child;
    char* env[] = {nullptr};
    const char* argv[] = {E2FSCK_BIN, "-n", "-E", "unshare_blocks", dev, nullptr};
    if (posix_spawn(&child, E2FSCK_BIN, nullptr, nullptr, const_cast<char**>(argv), env)) {
        WriteFdFmt(fd, "failed to e2fsck to check deduplication: %s\n", strerror(errno));
        return false;
    }
    int status = 0;
    int ret = TEMP_FAILURE_RETRY(waitpid(child, &status, 0));
    if (ret < 0) {
        WriteFdFmt(fd, "failed to get e2fsck status: %s\n", strerror(errno));
        return false;
    }
    if (!WIFEXITED(status)) {
        WriteFdFmt(fd, "e2fsck exited abnormally with status %d\n", status);
        return false;
    }
    int rc = WEXITSTATUS(status);
    if (rc != 0) {
        WriteFdFmt(fd,
                   "%s is deduplicated, and an e2fsck check failed. It might not "
                   "have enough free-space to be remounted as writable.\n",
                   dev);
        return false;
    }
    return true;
}

static unsigned long get_mount_flags(int fd, const char* dir) {
    struct statvfs st_vfs;
    if (statvfs(dir, &st_vfs) == -1) {
        // Even though we could not get the original mount flags, assume that
        // the mount was originally read-only.
        WriteFdFmt(fd, "statvfs of the %s mount failed: %s.\n", dir, strerror(errno));
        return MS_RDONLY;
    }
    return st_vfs.f_flag;
}

static bool remount_partition(int fd, const char* dir) {
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

    unsigned long remount_flags = get_mount_flags(fd, dir);
    remount_flags &= ~MS_RDONLY;
    remount_flags |= MS_REMOUNT;

    if (mount(dev.c_str(), dir, "none", remount_flags | MS_BIND, nullptr) == -1) {
        // This is useful for cases where the superblock is already marked as
        // read-write, but the mount itself is read-only, such as containers
        // where the remount with just MS_REMOUNT is forbidden by the kernel.
        WriteFdFmt(fd, "remount of the %s mount failed: %s.\n", dir, strerror(errno));
        return false;
    }
    if (mount(dev.c_str(), dir, "none", MS_REMOUNT, nullptr) == -1) {
        WriteFdFmt(fd, "remount of the %s superblock failed: %s\n", dir, strerror(errno));
        return false;
    }
    return true;
}

static void reboot_for_remount(int fd, bool need_fsck) {
    std::string reboot_cmd = "reboot";
    if (need_fsck) {
        const std::vector<std::string> options = {"--fsck_unshare_blocks"};
        std::string err;
        if (!write_bootloader_message(options, &err)) {
            WriteFdFmt(fd, "Failed to set bootloader message: %s\n", err.c_str());
            return;
        }

        WriteFdExactly(fd,
                       "The device will now reboot to recovery and attempt "
                       "un-deduplication.\n");
        reboot_cmd = "reboot,recovery";
    }

    sync();
    android::base::SetProperty(ANDROID_RB_PROPERTY, reboot_cmd.c_str());
}

void remount_service(android::base::unique_fd fd, const std::string& cmd) {
    bool user_requested_reboot = cmd != "-R";

    if (getuid() != 0) {
        WriteFdExactly(fd.get(), "Not running as root. Try \"adb root\" first.\n");
        return;
    }

    bool system_verified = !(android::base::GetProperty("partition.system.verified", "").empty());
    bool vendor_verified = !(android::base::GetProperty("partition.vendor.verified", "").empty());

    std::vector<std::string> partitions = {"/odm", "/oem", "/product", "/vendor"};
    if (android::base::GetBoolProperty("ro.build.system_root_image", false)) {
        partitions.push_back("/");
    } else {
        partitions.push_back("/system");
    }

    // Find partitions that are deduplicated, and can be un-deduplicated.
    std::set<std::string> dedup;
    for (const auto& partition : partitions) {
        std::string dev = find_mount(partition.c_str(), partition == "/");
        if (dev.empty() || !fs_has_shared_blocks(dev.c_str())) {
            continue;
        }
        if (can_unshare_blocks(fd.get(), dev.c_str())) {
            dedup.emplace(partition);
        }
    }

    bool verity_enabled = (system_verified || vendor_verified);

    // Reboot now if the user requested it (and an operation needs a reboot).
    if (user_requested_reboot) {
        if (!dedup.empty() || verity_enabled) {
            if (verity_enabled) {
                set_verity_enabled_state_service(android::base::unique_fd(dup(fd.get())), false);
            }
            reboot_for_remount(fd.get(), !dedup.empty());
            return;
        }
        WriteFdExactly(fd.get(), "No reboot needed, skipping -R.\n");
    }

    // If we need to disable-verity, but we also need to perform a recovery
    // fsck for deduplicated partitions, hold off on warning about verity. We
    // can handle both verity and the recovery fsck in the same reboot cycle.
    if (verity_enabled && dedup.empty()) {
        // Allow remount but warn of likely bad effects
        bool both = system_verified && vendor_verified;
        WriteFdFmt(fd.get(), "dm_verity is enabled on the %s%s%s partition%s.\n",
                   system_verified ? "system" : "", both ? " and " : "",
                   vendor_verified ? "vendor" : "", both ? "s" : "");
        WriteFdExactly(fd.get(),
                       "Use \"adb disable-verity\" to disable verity.\n"
                       "If you do not, remount may succeed, however, you will still "
                       "not be able to write to these volumes.\n");
        WriteFdExactly(fd.get(),
                       "Alternately, use \"adb remount -R\" to disable verity "
                       "and automatically reboot.\n");
    }

    bool success = true;
    for (const auto& partition : partitions) {
        // Don't try to remount partitions that need an fsck in recovery.
        if (dedup.count(partition)) {
            continue;
        }
        success &= remount_partition(fd.get(), partition.c_str());
    }

    if (!dedup.empty()) {
        WriteFdExactly(fd.get(),
                       "The following partitions are deduplicated and cannot "
                       "yet be remounted:\n");
        for (const std::string& name : dedup) {
            WriteFdFmt(fd.get(), "  %s\n", name.c_str());
        }

        WriteFdExactly(fd.get(),
                       "To reboot and un-deduplicate the listed partitions, "
                       "please retry with adb remount -R.\n");
        if (system_verified || vendor_verified) {
            WriteFdExactly(fd.get(), "Note: verity will be automatically disabled after reboot.\n");
        }
        return;
    }

    if (!success) {
        WriteFdExactly(fd.get(), "remount failed\n");
    } else {
        WriteFdExactly(fd.get(), "remount succeeded\n");
    }
}
