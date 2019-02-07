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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <algorithm>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libgsi/libgsi.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>

#include "fs_mgr_priv.h"

using namespace std::literals;
using namespace android::dm;
using namespace android::fs_mgr;

namespace {

bool fs_mgr_access(const std::string& path) {
    auto save_errno = errno;
    auto ret = access(path.c_str(), F_OK) == 0;
    errno = save_errno;
    return ret;
}

// determine if a filesystem is available
bool fs_mgr_overlayfs_filesystem_available(const std::string& filesystem) {
    std::string filesystems;
    if (!android::base::ReadFileToString("/proc/filesystems", &filesystems)) return false;
    return filesystems.find("\t" + filesystem + "\n") != std::string::npos;
}

}  // namespace

#if ALLOW_ADBD_DISABLE_VERITY == 0  // If we are a user build, provide stubs

bool fs_mgr_overlayfs_mount_all(Fstab*) {
    return false;
}

std::vector<std::string> fs_mgr_overlayfs_required_devices(Fstab*) {
    return {};
}

bool fs_mgr_overlayfs_setup(const char*, const char*, bool* change) {
    if (change) *change = false;
    return false;
}

bool fs_mgr_overlayfs_teardown(const char*, bool* change) {
    if (change) *change = false;
    return false;
}

bool fs_mgr_overlayfs_is_setup() {
    return false;
}

#else  // ALLOW_ADBD_DISABLE_VERITY == 0

namespace {

// list of acceptable overlayfs backing storage
const auto kScratchMountPoint = "/mnt/scratch"s;
const auto kCacheMountPoint = "/cache"s;
const std::vector<const std::string> kOverlayMountPoints = {kScratchMountPoint, kCacheMountPoint};

// Return true if everything is mounted, but before adb is started.  Right
// after 'trigger load_persist_props_action' is done.
bool fs_mgr_boot_completed() {
    return android::base::GetBoolProperty("ro.persistent_properties.ready", false);
}

bool fs_mgr_is_dir(const std::string& path) {
    struct stat st;
    return !stat(path.c_str(), &st) && S_ISDIR(st.st_mode);
}

// Similar test as overlayfs workdir= validation in the kernel for read-write
// validation, except we use fs_mgr_work.  Covers space and storage issues.
bool fs_mgr_dir_is_writable(const std::string& path) {
    auto test_directory = path + "/fs_mgr_work";
    rmdir(test_directory.c_str());
    auto ret = !mkdir(test_directory.c_str(), 0700);
    return ret | !rmdir(test_directory.c_str());
}

// At less than 1% free space return value of false,
// means we will try to wrap with overlayfs.
bool fs_mgr_filesystem_has_space(const std::string& mount_point) {
    // If we have access issues to find out space remaining, return true
    // to prevent us trying to override with overlayfs.
    struct statvfs vst;
    if (statvfs(mount_point.c_str(), &vst)) return true;

    static constexpr int kPercentThreshold = 1;  // 1%

    return (vst.f_bfree >= (vst.f_blocks * kPercentThreshold / 100));
}

bool fs_mgr_overlayfs_enabled(FstabEntry* entry) {
    // readonly filesystem, can not be mount -o remount,rw
    // for squashfs, erofs or if free space is (near) zero making such a remount
    // virtually useless, or if there are shared blocks that prevent remount,rw
    if (!fs_mgr_filesystem_has_space(entry->mount_point)) {
        return true;
    }
    if (entry->fs_mgr_flags.logical) {
        fs_mgr_update_logical_partition(entry);
    }
    auto save_errno = errno;
    auto has_shared_blocks = fs_mgr_has_shared_blocks(entry->mount_point, entry->blk_device);
    errno = save_errno;
    return has_shared_blocks;
}

bool fs_mgr_rm_all(const std::string& path, bool* change = nullptr, int level = 0) {
    auto save_errno = errno;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        if (errno == ENOENT) {
            errno = save_errno;
            return true;
        }
        PERROR << "opendir " << path << " depth=" << level;
        if ((errno == EPERM) && (level != 0)) {
            errno = save_errno;
            return true;
        }
        return false;
    }
    dirent* entry;
    auto ret = true;
    while ((entry = readdir(dir.get()))) {
        if (("."s == entry->d_name) || (".."s == entry->d_name)) continue;
        auto file = path + "/" + entry->d_name;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            save_errno = errno;
            if (!lstat(file.c_str(), &st) && (st.st_mode & S_IFDIR)) entry->d_type = DT_DIR;
            errno = save_errno;
        }
        if (entry->d_type == DT_DIR) {
            ret &= fs_mgr_rm_all(file, change, level + 1);
            if (!rmdir(file.c_str())) {
                if (change) *change = true;
            } else {
                if (errno != ENOENT) ret = false;
                PERROR << "rmdir " << file << " depth=" << level;
            }
            continue;
        }
        if (!unlink(file.c_str())) {
            if (change) *change = true;
        } else {
            if (errno != ENOENT) ret = false;
            PERROR << "rm " << file << " depth=" << level;
        }
    }
    return ret;
}

const auto kUpperName = "upper"s;
const auto kWorkName = "work"s;
const auto kOverlayTopDir = "/overlay"s;

std::string fs_mgr_get_overlayfs_candidate(const std::string& mount_point) {
    if (!fs_mgr_is_dir(mount_point)) return "";
    const auto base = android::base::Basename(mount_point) + "/";
    for (const auto& overlay_mount_point : kOverlayMountPoints) {
        auto dir = overlay_mount_point + kOverlayTopDir + "/" + base;
        auto upper = dir + kUpperName;
        if (!fs_mgr_is_dir(upper)) continue;
        auto work = dir + kWorkName;
        if (!fs_mgr_is_dir(work)) continue;
        if (!fs_mgr_dir_is_writable(work)) continue;
        return dir;
    }
    return "";
}

const auto kLowerdirOption = "lowerdir="s;
const auto kUpperdirOption = "upperdir="s;

// default options for mount_point, returns empty string for none available.
std::string fs_mgr_get_overlayfs_options(const std::string& mount_point) {
    auto candidate = fs_mgr_get_overlayfs_candidate(mount_point);
    if (candidate.empty()) return "";
    auto ret = kLowerdirOption + mount_point + "," + kUpperdirOption + candidate + kUpperName +
               ",workdir=" + candidate + kWorkName;
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kOverrideCredsRequired) {
        ret += ",override_creds=off";
    }
    return ret;
}

const char* fs_mgr_mount_point(const char* mount_point) {
    if (!mount_point) return mount_point;
    if ("/"s != mount_point) return mount_point;
    return "/system";
}

bool fs_mgr_rw_access(const std::string& path) {
    if (path.empty()) return false;
    auto save_errno = errno;
    auto ret = access(path.c_str(), R_OK | W_OK) == 0;
    errno = save_errno;
    return ret;
}

bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point, bool overlay_only = true) {
    Fstab fstab;
    if (!ReadFstabFromFile("/proc/mounts", &fstab)) {
        return false;
    }
    const auto lowerdir = kLowerdirOption + mount_point;
    for (const auto& entry : fstab) {
        if (overlay_only && "overlay" != entry.fs_type && "overlayfs" != entry.fs_type) continue;
        if (mount_point != entry.mount_point) continue;
        if (!overlay_only) return true;
        const auto options = android::base::Split(entry.fs_options, ",");
        for (const auto& opt : options) {
            if (opt == lowerdir) {
                return true;
            }
        }
    }
    return false;
}

std::vector<std::string> fs_mgr_overlayfs_verity_enabled_list() {
    std::vector<std::string> ret;
    auto save_errno = errno;
    fs_mgr_update_verity_state(
            [&ret](const std::string& mount_point, int) { ret.emplace_back(mount_point); });
    if ((errno == ENOENT) || (errno == ENXIO)) errno = save_errno;
    return ret;
}

bool fs_mgr_wants_overlayfs(FstabEntry* entry) {
    // Don't check entries that are managed by vold.
    if (entry->fs_mgr_flags.vold_managed || entry->fs_mgr_flags.recovery_only) return false;

    // *_other doesn't want overlayfs.
    if (entry->fs_mgr_flags.slot_select_other) return false;

    // Only concerned with readonly partitions.
    if (!(entry->flags & MS_RDONLY)) return false;

    // If unbindable, do not allow overlayfs as this could expose us to
    // security issues.  On Android, this could also be used to turn off
    // the ability to overlay an otherwise acceptable filesystem since
    // /system and /vendor are never bound(sic) to.
    if (entry->flags & MS_UNBINDABLE) return false;

    if (!fs_mgr_overlayfs_enabled(entry)) return false;

    return true;
}
constexpr char kOverlayfsFileContext[] = "u:object_r:overlayfs_file:s0";

bool fs_mgr_overlayfs_setup_dir(const std::string& dir, std::string* overlay, bool* change) {
    auto ret = true;
    auto top = dir + kOverlayTopDir;
    if (setfscreatecon(kOverlayfsFileContext)) {
        ret = false;
        PERROR << "setfscreatecon " << kOverlayfsFileContext;
    }
    auto save_errno = errno;
    if (!mkdir(top.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << top;
    } else {
        errno = save_errno;
    }
    setfscreatecon(nullptr);

    if (overlay) *overlay = std::move(top);
    return ret;
}

bool fs_mgr_overlayfs_setup_one(const std::string& overlay, const std::string& mount_point,
                                bool* change) {
    auto ret = true;
    auto fsrec_mount_point = overlay + "/" + android::base::Basename(mount_point) + "/";

    if (setfscreatecon(kOverlayfsFileContext)) {
        ret = false;
        PERROR << "setfscreatecon " << kOverlayfsFileContext;
    }
    auto save_errno = errno;
    if (!mkdir(fsrec_mount_point.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << fsrec_mount_point;
    } else {
        errno = save_errno;
    }

    save_errno = errno;
    if (!mkdir((fsrec_mount_point + kWorkName).c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << fsrec_mount_point << kWorkName;
    } else {
        errno = save_errno;
    }
    setfscreatecon(nullptr);

    auto new_context = fs_mgr_get_context(mount_point);
    if (!new_context.empty() && setfscreatecon(new_context.c_str())) {
        ret = false;
        PERROR << "setfscreatecon " << new_context;
    }
    auto upper = fsrec_mount_point + kUpperName;
    save_errno = errno;
    if (!mkdir(upper.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "mkdir " << upper;
    } else {
        errno = save_errno;
    }
    if (!new_context.empty()) setfscreatecon(nullptr);

    return ret;
}

uint32_t fs_mgr_overlayfs_slot_number() {
    return SlotNumberForSlotSuffix(fs_mgr_get_slot_suffix());
}

const auto kPhysicalDevice = "/dev/block/by-name/"s;

std::string fs_mgr_overlayfs_super_device(uint32_t slot_number) {
    return kPhysicalDevice + fs_mgr_get_super_partition_name(slot_number);
}

bool fs_mgr_overlayfs_has_logical(const Fstab& fstab) {
    for (const auto& entry : fstab) {
        if (entry.fs_mgr_flags.logical) {
            return true;
        }
    }
    return false;
}

void fs_mgr_overlayfs_umount_scratch() {
    // Lazy umount will allow us to move on and possibly later
    // establish a new fresh mount without requiring a reboot should
    // the developer wish to restart.  Old references should melt
    // away or have no data.  Main goal is to shut the door on the
    // current overrides with an expectation of a subsequent reboot,
    // thus any errors here are ignored.
    umount2(kScratchMountPoint.c_str(), MNT_DETACH);
    LINFO << "umount(" << kScratchMountPoint << ")";
    rmdir(kScratchMountPoint.c_str());
}

// reduce 'DM_DEV_STATUS failed for scratch: No such device or address' noise
std::string scratch_device_cache;

bool fs_mgr_overlayfs_teardown_scratch(const std::string& overlay, bool* change) {
    // umount and delete kScratchMountPoint storage if we have logical partitions
    if (overlay != kScratchMountPoint) return true;
    scratch_device_cache.erase();
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device)) return true;

    auto save_errno = errno;
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        fs_mgr_overlayfs_umount_scratch();
    }
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        errno = save_errno;
        return true;
    }
    const auto partition_name = android::base::Basename(kScratchMountPoint);
    if (builder->FindPartition(partition_name) == nullptr) {
        errno = save_errno;
        return true;
    }
    builder->RemovePartition(partition_name);
    auto metadata = builder->Export();
    if (metadata && UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
        if (change) *change = true;
        if (!DestroyLogicalPartition(partition_name, 0s)) return false;
    } else {
        LERROR << "delete partition " << overlay;
        return false;
    }
    errno = save_errno;
    return true;
}

bool fs_mgr_overlayfs_teardown_one(const std::string& overlay, const std::string& mount_point,
                                   bool* change) {
    const auto top = overlay + kOverlayTopDir;

    if (!fs_mgr_access(top)) return fs_mgr_overlayfs_teardown_scratch(overlay, change);

    auto cleanup_all = mount_point.empty();
    const auto partition_name = android::base::Basename(mount_point);
    const auto oldpath = top + (cleanup_all ? "" : ("/" + partition_name));
    const auto newpath = cleanup_all ? overlay + "/." + kOverlayTopDir.substr(1) + ".teardown"
                                     : top + "/." + partition_name + ".teardown";
    auto ret = fs_mgr_rm_all(newpath);
    auto save_errno = errno;
    if (!rename(oldpath.c_str(), newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "mv " << oldpath << " " << newpath;
    } else {
        errno = save_errno;
    }
    ret &= fs_mgr_rm_all(newpath, change);
    save_errno = errno;
    if (!rmdir(newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "rmdir " << newpath;
    } else {
        errno = save_errno;
    }
    if (!cleanup_all) {
        save_errno = errno;
        if (!rmdir(top.c_str())) {
            if (change) *change = true;
            cleanup_all = true;
        } else if (errno == ENOTEMPTY) {
            cleanup_all = true;
            // cleanup all if the content is all hidden (leading .)
            std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(top.c_str()), closedir);
            if (!dir) {
                PERROR << "opendir " << top;
            } else {
                dirent* entry;
                while ((entry = readdir(dir.get()))) {
                    if (entry->d_name[0] != '.') {
                        cleanup_all = false;
                        break;
                    }
                }
            }
            errno = save_errno;
        } else if (errno == ENOENT) {
            cleanup_all = true;
            errno = save_errno;
        } else {
            ret = false;
            PERROR << "rmdir " << top;
        }
    }
    if (cleanup_all) ret &= fs_mgr_overlayfs_teardown_scratch(overlay, change);
    return ret;
}

bool fs_mgr_overlayfs_mount(const std::string& mount_point) {
    auto options = fs_mgr_get_overlayfs_options(mount_point);
    if (options.empty()) return false;

    // hijack __mount() report format to help triage
    auto report = "__mount(source=overlay,target="s + mount_point + ",type=overlay";
    const auto opt_list = android::base::Split(options, ",");
    for (const auto& opt : opt_list) {
        if (android::base::StartsWith(opt, kUpperdirOption)) {
            report = report + "," + opt;
            break;
        }
    }
    report = report + ")=";

    auto ret = mount("overlay", mount_point.c_str(), "overlay", MS_RDONLY | MS_RELATIME,
                     options.c_str());
    if (ret) {
        PERROR << report << ret;
        return false;
    } else {
        LINFO << report << ret;
        return true;
    }
}

std::vector<std::string> fs_mgr_candidate_list(Fstab* fstab, const char* mount_point = nullptr) {
    std::vector<std::string> mounts;
    auto verity = fs_mgr_overlayfs_verity_enabled_list();
    for (auto& entry : *fstab) {
        if (!fs_mgr_wants_overlayfs(&entry)) continue;
        std::string new_mount_point(fs_mgr_mount_point(entry.mount_point.c_str()));
        if (mount_point && (new_mount_point != mount_point)) continue;
        if (std::find(verity.begin(), verity.end(), android::base::Basename(new_mount_point)) !=
            verity.end()) {
            continue;
        }
        auto duplicate_or_more_specific = false;
        for (auto it = mounts.begin(); it != mounts.end();) {
            if ((*it == new_mount_point) ||
                (android::base::StartsWith(new_mount_point, *it + "/"))) {
                duplicate_or_more_specific = true;
                break;
            }
            if (android::base::StartsWith(*it, new_mount_point + "/")) {
                it = mounts.erase(it);
            } else {
                ++it;
            }
        }
        if (!duplicate_or_more_specific) mounts.emplace_back(new_mount_point);
    }

    // if not itemized /system or /, system as root, fake one up?

    // do we want or need to?
    if (mount_point && ("/system"s != mount_point)) return mounts;
    if (std::find(mounts.begin(), mounts.end(), "/system") != mounts.end()) return mounts;

    // fs_mgr_overlayfs_verity_enabled_list says not to?
    if (std::find(verity.begin(), verity.end(), "system") != verity.end()) return mounts;

    // confirm that fstab is missing system
    if (GetEntryForMountPoint(fstab, "/") != nullptr ||
        GetEntryForMountPoint(fstab, "/system") != nullptr) {
        return mounts;
    }

    // We have a stunted fstab (w/o system or / ) passed in by the caller,
    // verity claims are assumed accurate because they are collected internally
    // from fs_mgr_fstab_default() from within fs_mgr_update_verity_state(),
    // Can (re)evaluate /system with impunity since we know it is ever-present.
    mounts.emplace_back("/system");
    return mounts;
}

// Mount kScratchMountPoint
bool fs_mgr_overlayfs_mount_scratch(const std::string& device_path, const std::string mnt_type,
                                    bool readonly = false) {
    if (readonly) {
        if (!fs_mgr_access(device_path)) return false;
    } else {
        if (!fs_mgr_rw_access(device_path)) return false;
    }

    if (setfscreatecon(kOverlayfsFileContext)) {
        PERROR << "setfscreatecon " << kOverlayfsFileContext;
    }
    if (mkdir(kScratchMountPoint.c_str(), 0755) && (errno != EEXIST)) {
        PERROR << "create " << kScratchMountPoint;
    }

    FstabEntry entry;
    entry.blk_device = device_path;
    entry.mount_point = kScratchMountPoint;
    entry.fs_type = mnt_type;
    entry.flags = MS_RELATIME;
    if (readonly) {
        entry.flags |= MS_RDONLY;
    } else {
        fs_mgr_set_blk_ro(device_path, false);
    }
    auto save_errno = errno;
    auto mounted = fs_mgr_do_mount_one(entry) == 0;
    if (!mounted) {
        if (mnt_type == "f2fs") {
            entry.fs_type = "ext4";
        } else {
            entry.fs_type = "f2fs";
        }
        mounted = fs_mgr_do_mount_one(entry) == 0;
        if (!mounted) save_errno = errno;
    }
    setfscreatecon(nullptr);
    if (!mounted) rmdir(kScratchMountPoint.c_str());
    errno = save_errno;
    return mounted;
}

const std::string kMkF2fs("/system/bin/make_f2fs");
const std::string kMkExt4("/system/bin/mke2fs");

// Only a suggestion for _first_ try during mounting
std::string fs_mgr_overlayfs_scratch_mount_type() {
    if (!access(kMkF2fs.c_str(), X_OK) && fs_mgr_overlayfs_filesystem_available("f2fs")) {
        return "f2fs";
    }
    if (!access(kMkExt4.c_str(), X_OK) && fs_mgr_overlayfs_filesystem_available("ext4")) {
        return "ext4";
    }
    return "auto";
}

std::string fs_mgr_overlayfs_scratch_device() {
    if (!scratch_device_cache.empty()) return scratch_device_cache;

    // Is this a multiple super device (retrofit)?
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    auto path = fs_mgr_overlayfs_super_device(slot_number == 0);
    if (super_device == path) {
        // Create from within single super device;
        auto& dm = DeviceMapper::Instance();
        const auto partition_name = android::base::Basename(kScratchMountPoint);
        if (!dm.GetDmDevicePathByName(partition_name, &path)) {
            // non-DAP A/B device?
            if (fs_mgr_access(super_device)) return "";
            path = kPhysicalDevice + "system" + (slot_number ? "_a" : "_b");
        }
    }
    return scratch_device_cache = path;
}

bool fs_mgr_overlayfs_make_scratch(const std::string& scratch_device, const std::string& mnt_type) {
    // Force mkfs by design for overlay support of adb remount, simplify and
    // thus do not rely on fsck to correct problems that could creep in.
    auto command = ""s;
    if (mnt_type == "f2fs") {
        command = kMkF2fs + " -w 4096 -f -d1 -l" + android::base::Basename(kScratchMountPoint);
    } else if (mnt_type == "ext4") {
        command = kMkExt4 + " -F -b 4096 -t ext4 -m 0 -O has_journal -M " + kScratchMountPoint;
    } else {
        errno = ESRCH;
        LERROR << mnt_type << " has no mkfs cookbook";
        return false;
    }
    command += " " + scratch_device;
    fs_mgr_set_blk_ro(scratch_device, false);
    auto ret = system(command.c_str());
    if (ret) {
        LERROR << "make " << mnt_type << " filesystem on " << scratch_device << " return=" << ret;
        return false;
    }
    return true;
}

bool fs_mgr_overlayfs_create_scratch(const Fstab& fstab, std::string* scratch_device,
                                     bool* partition_exists, bool* change) {
    *scratch_device = fs_mgr_overlayfs_scratch_device();
    *partition_exists = fs_mgr_rw_access(*scratch_device);
    auto partition_create = !*partition_exists;
    // Do we need to create a logical "scratch" partition?
    if (!partition_create && android::base::StartsWith(*scratch_device, kPhysicalDevice)) {
        return true;
    }
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device)) return false;
    if (!fs_mgr_overlayfs_has_logical(fstab)) return false;
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        LERROR << "open " << super_device << " metadata";
        return false;
    }
    const auto partition_name = android::base::Basename(kScratchMountPoint);
    auto partition = builder->FindPartition(partition_name);
    *partition_exists = partition != nullptr;
    auto changed = false;
    if (!*partition_exists) {
        partition = builder->AddPartition(partition_name, LP_PARTITION_ATTR_NONE);
        if (!partition) {
            LERROR << "create " << partition_name;
            return false;
        }
        changed = true;
    }
    // Take half of free space, minimum 512MB or maximum free - margin.
    static constexpr auto kMinimumSize = uint64_t(512 * 1024 * 1024);
    if (partition->size() < kMinimumSize) {
        auto partition_size =
                builder->AllocatableSpace() - builder->UsedSpace() + partition->size();
        if ((partition_size > kMinimumSize) || !partition->size()) {
            // Leave some space for free space jitter of a few erase
            // blocks, in case they are needed for any individual updates
            // to any other partition that needs to be flashed while
            // overlayfs is in force.  Of course if margin_size is not
            // enough could normally get a flash failure, so
            // ResizePartition() will delete the scratch partition in
            // order to fulfill.  Deleting scratch will destroy all of
            // the adb remount overrides :-( .
            auto margin_size = uint64_t(3 * 256 * 1024);
            BlockDeviceInfo info;
            if (builder->GetBlockDeviceInfo(partition_name, &info)) {
                margin_size = 3 * info.logical_block_size;
            }
            partition_size = std::max(std::min(kMinimumSize, partition_size - margin_size),
                                      partition_size / 2);
            if (partition_size > partition->size()) {
                if (!builder->ResizePartition(partition, partition_size)) {
                    LERROR << "resize " << partition_name;
                    return false;
                }
                if (!partition_create) DestroyLogicalPartition(partition_name, 10s);
                changed = true;
                *partition_exists = false;
            }
        }
    }
    // land the update back on to the partition
    if (changed) {
        auto metadata = builder->Export();
        if (!metadata || !UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
            LERROR << "add partition " << partition_name;
            return false;
        }

        if (change) *change = true;
    }

    if (changed || partition_create) {
        if (!CreateLogicalPartition(super_device, slot_number, partition_name, true, 0s,
                                    scratch_device))
            return false;

        if (change) *change = true;
    }
    return true;
}

// Create and mount kScratchMountPoint storage if we have logical partitions
bool fs_mgr_overlayfs_setup_scratch(const Fstab& fstab, bool* change) {
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) return true;

    std::string scratch_device;
    bool partition_exists;
    if (!fs_mgr_overlayfs_create_scratch(fstab, &scratch_device, &partition_exists, change)) {
        return false;
    }

    // If the partition exists, assume first that it can be mounted.
    auto mnt_type = fs_mgr_overlayfs_scratch_mount_type();
    if (partition_exists) {
        if (fs_mgr_overlayfs_mount_scratch(scratch_device, mnt_type)) {
            if (!fs_mgr_access(kScratchMountPoint + kOverlayTopDir) &&
                !fs_mgr_filesystem_has_space(kScratchMountPoint)) {
                // declare it useless, no overrides and no free space
                fs_mgr_overlayfs_umount_scratch();
            } else {
                if (change) *change = true;
                return true;
            }
        }
        // partition existed, but was not initialized; fall through to make it.
        errno = 0;
    }

    if (!fs_mgr_overlayfs_make_scratch(scratch_device, mnt_type)) return false;

    if (change) *change = true;

    return fs_mgr_overlayfs_mount_scratch(scratch_device, mnt_type);
}

bool fs_mgr_overlayfs_scratch_can_be_mounted(const std::string& scratch_device) {
    if (scratch_device.empty()) return false;
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) return false;
    if (android::base::StartsWith(scratch_device, kPhysicalDevice)) return true;
    if (fs_mgr_rw_access(scratch_device)) return true;
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device)) return false;
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) return false;
    return builder->FindPartition(android::base::Basename(kScratchMountPoint)) != nullptr;
}

bool fs_mgr_overlayfs_invalid() {
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) return true;

    // in recovery, fastbootd, or gsi mode, not allowed!
    if (fs_mgr_access("/system/bin/recovery")) return true;
    if (android::gsi::IsGsiRunning()) return true;

    return false;
}

}  // namespace

bool fs_mgr_overlayfs_mount_all(Fstab* fstab) {
    auto ret = false;
    if (fs_mgr_overlayfs_invalid()) return ret;

    auto scratch_can_be_mounted = true;
    for (const auto& mount_point : fs_mgr_candidate_list(fstab)) {
        if (fs_mgr_overlayfs_already_mounted(mount_point)) continue;
        if (scratch_can_be_mounted) {
            scratch_can_be_mounted = false;
            auto scratch_device = fs_mgr_overlayfs_scratch_device();
            if (fs_mgr_overlayfs_scratch_can_be_mounted(scratch_device) &&
                fs_mgr_wait_for_file(scratch_device, 10s)) {
                const auto mount_type = fs_mgr_overlayfs_scratch_mount_type();
                if (fs_mgr_overlayfs_mount_scratch(scratch_device, mount_type,
                                                   true /* readonly */)) {
                    auto has_overlayfs_dir = fs_mgr_access(kScratchMountPoint + kOverlayTopDir);
                    fs_mgr_overlayfs_umount_scratch();
                    if (has_overlayfs_dir) {
                        fs_mgr_overlayfs_mount_scratch(scratch_device, mount_type);
                    }
                }
            }
        }
        if (fs_mgr_overlayfs_mount(mount_point)) ret = true;
    }
    return ret;
}

std::vector<std::string> fs_mgr_overlayfs_required_devices(Fstab* fstab) {
    if (fs_mgr_overlayfs_invalid()) return {};

    if (GetEntryForMountPoint(fstab, kScratchMountPoint) != nullptr) {
        return {};
    }

    for (const auto& mount_point : fs_mgr_candidate_list(fstab)) {
        if (fs_mgr_overlayfs_already_mounted(mount_point)) continue;
        auto device = fs_mgr_overlayfs_scratch_device();
        if (!fs_mgr_overlayfs_scratch_can_be_mounted(device)) break;
        return {device};
    }
    return {};
}

// Returns false if setup not permitted, errno set to last error.
// If something is altered, set *change.
bool fs_mgr_overlayfs_setup(const char* backing, const char* mount_point, bool* change) {
    if (change) *change = false;
    auto ret = false;
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) return ret;
    if (!fs_mgr_boot_completed()) {
        errno = EBUSY;
        PERROR << "setup";
        return ret;
    }

    auto save_errno = errno;
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return false;
    }
    errno = save_errno;
    auto mounts = fs_mgr_candidate_list(&fstab, fs_mgr_mount_point(mount_point));
    if (mounts.empty()) return ret;

    std::string dir;
    for (const auto& overlay_mount_point : kOverlayMountPoints) {
        if (backing && backing[0] && (overlay_mount_point != backing)) continue;
        if (overlay_mount_point == kScratchMountPoint) {
            if (!fs_mgr_overlayfs_setup_scratch(fstab, change)) continue;
        } else {
            if (GetEntryForMountPoint(&fstab, overlay_mount_point) == nullptr) {
                continue;
            }
        }
        dir = overlay_mount_point;
        break;
    }
    if (dir.empty()) {
        if (change && *change) errno = ESRCH;
        if (errno == EPERM) errno = save_errno;
        return ret;
    }

    std::string overlay;
    ret |= fs_mgr_overlayfs_setup_dir(dir, &overlay, change);
    for (const auto& fsrec_mount_point : mounts) {
        ret |= fs_mgr_overlayfs_setup_one(overlay, fsrec_mount_point, change);
    }
    return ret;
}

// Returns false if teardown not permitted, errno set to last error.
// If something is altered, set *change.
bool fs_mgr_overlayfs_teardown(const char* mount_point, bool* change) {
    if (change) *change = false;
    mount_point = fs_mgr_mount_point(mount_point);
    auto ret = true;
    // If scratch exists, but is not mounted, lets gain access to clean
    // specific override entries.
    auto mount_scratch = false;
    if ((mount_point != nullptr) && !fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        auto scratch_device = fs_mgr_overlayfs_scratch_device();
        if (scratch_device.empty()) {
            auto slot_number = fs_mgr_overlayfs_slot_number();
            auto super_device = fs_mgr_overlayfs_super_device(slot_number);
            const auto partition_name = android::base::Basename(kScratchMountPoint);
            CreateLogicalPartition(super_device, slot_number, partition_name, true, 0s,
                                   &scratch_device);
        }
        mount_scratch = fs_mgr_overlayfs_mount_scratch(scratch_device,
                                                       fs_mgr_overlayfs_scratch_mount_type());
    }
    for (const auto& overlay_mount_point : kOverlayMountPoints) {
        ret &= fs_mgr_overlayfs_teardown_one(overlay_mount_point, mount_point ?: "", change);
    }
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) {
        // After obligatory teardown to make sure everything is clean, but if
        // we didn't want overlayfs in the the first place, we do not want to
        // waste time on a reboot (or reboot request message).
        if (change) *change = false;
    }
    // And now that we did what we could, lets inform
    // caller that there may still be more to do.
    if (!fs_mgr_boot_completed()) {
        errno = EBUSY;
        PERROR << "teardown";
        ret = false;
    }
    if (mount_scratch) fs_mgr_overlayfs_umount_scratch();

    return ret;
}

bool fs_mgr_overlayfs_is_setup() {
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) return true;
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return false;
    }
    if (fs_mgr_overlayfs_invalid()) return false;
    for (const auto& mount_point : fs_mgr_candidate_list(&fstab)) {
        if (fs_mgr_overlayfs_already_mounted(mount_point)) return true;
    }
    return false;
}

#endif  // ALLOW_ADBD_DISABLE_VERITY != 0

bool fs_mgr_has_shared_blocks(const std::string& mount_point, const std::string& dev) {
    struct statfs fs;
    if ((statfs((mount_point + "/lost+found").c_str(), &fs) == -1) ||
        (fs.f_type != EXT4_SUPER_MAGIC)) {
        return false;
    }

    android::base::unique_fd fd(open(dev.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    struct ext4_super_block sb;
    if ((TEMP_FAILURE_RETRY(lseek64(fd, 1024, SEEK_SET)) < 0) ||
        (TEMP_FAILURE_RETRY(read(fd, &sb, sizeof(sb))) < 0)) {
        return false;
    }

    struct fs_info info;
    if (ext4_parse_sb(&sb, &info) < 0) return false;

    return (info.feat_ro_compat & EXT4_FEATURE_RO_COMPAT_SHARED_BLOCKS) != 0;
}

std::string fs_mgr_get_context(const std::string& mount_point) {
    char* ctx = nullptr;
    if (getfilecon(mount_point.c_str(), &ctx) == -1) {
        return "";
    }

    std::string context(ctx);
    free(ctx);
    return context;
}

OverlayfsValidResult fs_mgr_overlayfs_valid() {
    // Overlayfs available in the kernel, and patched for override_creds?
    if (fs_mgr_access("/sys/module/overlay/parameters/override_creds")) {
        return OverlayfsValidResult::kOverrideCredsRequired;
    }
    if (!fs_mgr_overlayfs_filesystem_available("overlay")) {
        return OverlayfsValidResult::kNotSupported;
    }
    struct utsname uts;
    if (uname(&uts) == -1) {
        return OverlayfsValidResult::kNotSupported;
    }
    int major, minor;
    if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
        return OverlayfsValidResult::kNotSupported;
    }
    if (major < 4) {
        return OverlayfsValidResult::kOk;
    }
    if (major > 4) {
        return OverlayfsValidResult::kNotSupported;
    }
    if (minor > 6) {
        return OverlayfsValidResult::kNotSupported;
    }
    return OverlayfsValidResult::kOk;
}
