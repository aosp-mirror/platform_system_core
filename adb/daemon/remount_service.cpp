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

#include <memory>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fs_mgr.h>
#include <fs_mgr_overlayfs.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "set_verity_enable_state_service.h"

using android::base::Realpath;
using android::fs_mgr::Fstab;
using android::fs_mgr::ReadDefaultFstab;

// Returns the last device used to mount a directory in /proc/mounts.
// This will find overlayfs entry where upperdir=lowerdir, to make sure
// remount is associated with the correct directory.
static std::string find_proc_mount(const char* dir) {
    std::unique_ptr<FILE, int(*)(FILE*)> fp(setmntent("/proc/mounts", "r"), endmntent);
    std::string mnt_fsname;
    if (!fp) return mnt_fsname;

    // dir might be a symlink, e.g., /product -> /system/product in GSI.
    std::string canonical_path;
    if (!Realpath(dir, &canonical_path)) {
        PLOG(ERROR) << "Realpath failed: " << dir;
    }

    mntent* e;
    while ((e = getmntent(fp.get())) != nullptr) {
        if (canonical_path == e->mnt_dir) {
            mnt_fsname = e->mnt_fsname;
        }
    }
    return mnt_fsname;
}

// Returns the device used to mount a directory in the fstab.
static std::string find_fstab_mount(const char* dir) {
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return "";
    }

    auto entry = std::find_if(fstab.begin(), fstab.end(),
                              [&dir](const auto& entry) { return entry.mount_point == dir; });
    if (entry == fstab.end()) {
        return "";
    }
    if (entry->fs_mgr_flags.logical) {
        fs_mgr_update_logical_partition(&(*entry));
    }
    return entry->blk_device;
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

bool dev_is_overlayfs(const std::string& dev) {
    return (dev == "overlay") || (dev == "overlayfs");
}

bool make_block_device_writable(const std::string& dev) {
    if (dev_is_overlayfs(dev)) return true;
    int fd = unix_open(dev, O_RDONLY | O_CLOEXEC);
    if (fd == -1) {
        return false;
    }

    int OFF = 0;
    bool result = (ioctl(fd, BLKROSET, &OFF) != -1);
    unix_close(fd);
    return result;
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
    if (is_root && dev_is_overlayfs(find_mount("/system", false))) {
        dir = "/system";
        is_root = false;
    }
    std::string dev = find_mount(dir, is_root);
    if (is_root && dev.empty()) {
        // The fstab entry will be /system if the device switched roots during
        // first-stage init.
        dev = find_mount("/system", true);
    }
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

static void try_unmount_bionic(int fd) {
    static constexpr const char* kBionic = "/bionic";
    struct statfs buf;
    if (statfs(kBionic, &buf) == -1) {
        WriteFdFmt(fd, "statfs of the %s mount failed: %s.\n", kBionic, strerror(errno));
        return;
    }
    if (buf.f_flags & ST_RDONLY) {
        // /bionic is on a read-only partition; can happen for
        // non-system-as-root-devices. Don' try to unmount.
        return;
    }
    // Success/Fail of the actual remount will be reported by the function.
    remount_partition(fd, kBionic);
    return;
}

void remount_service(unique_fd fd, const std::string& cmd) {
    bool user_requested_reboot = cmd == "-R";

    if (getuid() != 0) {
        WriteFdExactly(fd.get(), "Not running as root. Try \"adb root\" first.\n");
        return;
    }

    bool system_verified = !(android::base::GetProperty("partition.system.verified", "").empty());
    bool vendor_verified = !(android::base::GetProperty("partition.vendor.verified", "").empty());

    std::vector<std::string> partitions{"/",        "/odm",   "/oem", "/product_services",
                                        "/product", "/vendor"};

    if (system_verified || vendor_verified) {
        // Disable verity automatically (reboot will be required).
        set_verity_enabled_state_service(unique_fd(dup(fd.get())), false);

        // If overlayfs is not supported, we try and remount or set up
        // un-deduplication. If it is supported, we can go ahead and wait for
        // a reboot.
        if (fs_mgr_overlayfs_valid() != OverlayfsValidResult::kNotSupported) {
            if (user_requested_reboot) {
                if (android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot")) {
                    WriteFdExactly(fd.get(), "rebooting device\n");
                } else {
                    WriteFdExactly(fd.get(), "reboot failed\n");
                }
            }
            return;
        }
    } else if (fs_mgr_overlayfs_setup()) {
        // If we can use overlayfs, lets get it in place first before we
        // struggle with determining deduplication operations.
        Fstab fstab;
        if (ReadDefaultFstab(&fstab) && fs_mgr_overlayfs_mount_all(&fstab)) {
            WriteFdExactly(fd.get(), "overlayfs mounted\n");
        }
    }

    // If overlayfs is supported, we don't bother trying to un-deduplicate
    // partitions.
    std::set<std::string> dedup;
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) {
        // Find partitions that are deduplicated, and can be un-deduplicated.
        for (const auto& part : partitions) {
            auto partition = part;
            if ((part == "/") && !find_mount("/system", false).empty()) partition = "/system";
            std::string dev = find_mount(partition.c_str(), partition == "/");
            if (dev.empty() || !fs_mgr_has_shared_blocks(partition, dev)) {
                continue;
            }
            if (can_unshare_blocks(fd.get(), dev.c_str())) {
                dedup.emplace(partition);
            }
        }

        // Reboot now if the user requested it (and an operation needs a reboot).
        if (user_requested_reboot) {
            if (!dedup.empty()) {
                reboot_for_remount(fd.get(), !dedup.empty());
                return;
            }
            WriteFdExactly(fd.get(), "No reboot needed, skipping -R.\n");
        }
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

    try_unmount_bionic(fd.get());

    if (!success) {
        WriteFdExactly(fd.get(), "remount failed\n");
    } else {
        WriteFdExactly(fd.get(), "remount succeeded\n");
    }
}
