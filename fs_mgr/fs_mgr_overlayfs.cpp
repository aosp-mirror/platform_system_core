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
#include <fs_mgr/file_wait.h>
#include <fs_mgr_dm_linear.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <libdm/dm.h>
#include <libfiemap/image_manager.h>
#include <libgsi/libgsi.h>
#include <liblp/builder.h>
#include <liblp/liblp.h>
#include <storage_literals/storage_literals.h>

#include "fs_mgr_priv.h"
#include "libfiemap/utility.h"

using namespace std::literals;
using namespace android::dm;
using namespace android::fs_mgr;
using namespace android::storage_literals;
using android::fiemap::FilesystemHasReliablePinning;
using android::fiemap::IImageManager;

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

Fstab fs_mgr_overlayfs_candidate_list(const Fstab&) {
    return {};
}

bool fs_mgr_overlayfs_mount_all(Fstab*) {
    return false;
}

std::vector<std::string> fs_mgr_overlayfs_required_devices(Fstab*) {
    return {};
}

bool fs_mgr_overlayfs_setup(const char*, const char*, bool* change, bool) {
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

namespace android {
namespace fs_mgr {

void MapScratchPartitionIfNeeded(Fstab*, const std::function<bool(const std::set<std::string>&)>&) {
}

void TeardownAllOverlayForMountPoint(const std::string&) {}

}  // namespace fs_mgr
}  // namespace android

#else  // ALLOW_ADBD_DISABLE_VERITY == 0

namespace {

bool fs_mgr_in_recovery() {
    // Check the existence of recovery binary instead of using the compile time
    // macro, because first-stage-init is compiled with __ANDROID_RECOVERY__
    // defined, albeit not in recovery. More details: system/core/init/README.md
    return fs_mgr_access("/system/bin/recovery");
}

bool fs_mgr_is_dsu_running() {
    // Since android::gsi::CanBootIntoGsi() or android::gsi::MarkSystemAsGsi() is
    // never called in recovery, the return value of android::gsi::IsGsiRunning()
    // is not well-defined. In this case, just return false as being in recovery
    // implies not running a DSU system.
    if (fs_mgr_in_recovery()) return false;
    auto saved_errno = errno;
    auto ret = android::gsi::IsGsiRunning();
    errno = saved_errno;
    return ret;
}

// list of acceptable overlayfs backing storage
const auto kScratchMountPoint = "/mnt/scratch"s;
const auto kCacheMountPoint = "/cache"s;

std::vector<const std::string> OverlayMountPoints() {
    // Never fallback to legacy cache mount point if within a DSU system,
    // because running a DSU system implies the device supports dynamic
    // partitions, which means legacy cache mustn't be used.
    if (fs_mgr_is_dsu_running()) {
        return {kScratchMountPoint};
    }
    return {kScratchMountPoint, kCacheMountPoint};
}

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

// At less than 1% or 8MB of free space return value of false,
// means we will try to wrap with overlayfs.
bool fs_mgr_filesystem_has_space(const std::string& mount_point) {
    // If we have access issues to find out space remaining, return true
    // to prevent us trying to override with overlayfs.
    struct statvfs vst;
    auto save_errno = errno;
    if (statvfs(mount_point.c_str(), &vst)) {
        errno = save_errno;
        return true;
    }

    static constexpr int kPercentThreshold = 1;                       // 1%
    static constexpr unsigned long kSizeThreshold = 8 * 1024 * 1024;  // 8MB

    return (vst.f_bfree >= (vst.f_blocks * kPercentThreshold / 100)) &&
           (vst.f_bfree * vst.f_bsize) >= kSizeThreshold;
}

const auto kPhysicalDevice = "/dev/block/by-name/"s;
constexpr char kScratchImageMetadata[] = "/metadata/gsi/remount/lp_metadata";

// Note: this is meant only for recovery/first-stage init.
bool ScratchIsOnData() {
    // The scratch partition of DSU is managed by gsid.
    if (fs_mgr_is_dsu_running()) {
        return false;
    }
    return fs_mgr_access(kScratchImageMetadata);
}

bool fs_mgr_update_blk_device(FstabEntry* entry) {
    if (entry->fs_mgr_flags.logical) {
        fs_mgr_update_logical_partition(entry);
    }
    if (fs_mgr_access(entry->blk_device)) {
        return true;
    }
    if (entry->blk_device != "/dev/root") {
        return false;
    }

    // special case for system-as-root (taimen and others)
    auto blk_device = kPhysicalDevice + "system";
    if (!fs_mgr_access(blk_device)) {
        blk_device += fs_mgr_get_slot_suffix();
        if (!fs_mgr_access(blk_device)) {
            return false;
        }
    }
    entry->blk_device = blk_device;
    return true;
}

bool fs_mgr_overlayfs_enabled(FstabEntry* entry) {
    // readonly filesystem, can not be mount -o remount,rw
    // for squashfs, erofs or if free space is (near) zero making such a remount
    // virtually useless, or if there are shared blocks that prevent remount,rw
    if (!fs_mgr_filesystem_has_space(entry->mount_point)) {
        return true;
    }

    // blk_device needs to be setup so we can check superblock.
    // If we fail here, because during init first stage and have doubts.
    if (!fs_mgr_update_blk_device(entry)) {
        return true;
    }

    // check if ext4 de-dupe
    auto save_errno = errno;
    auto has_shared_blocks = fs_mgr_has_shared_blocks(entry->mount_point, entry->blk_device);
    if (!has_shared_blocks && (entry->mount_point == "/system")) {
        has_shared_blocks = fs_mgr_has_shared_blocks("/", entry->blk_device);
    }
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
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
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

const std::string fs_mgr_mount_point(const std::string& mount_point) {
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
    auto save_errno = errno;
    if (!ReadFstabFromFile("/proc/mounts", &fstab)) {
        return false;
    }
    errno = save_errno;
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
    if (fs_mgr_overlayfs_already_mounted(mount_point)) return ret;
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

bool fs_mgr_overlayfs_teardown_scratch(const std::string& overlay, bool* change) {
    // umount and delete kScratchMountPoint storage if we have logical partitions
    if (overlay != kScratchMountPoint) return true;

    // Validation check.
    if (fs_mgr_is_dsu_running()) {
        LERROR << "Destroying DSU scratch is not allowed.";
        return false;
    }

    auto save_errno = errno;
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        fs_mgr_overlayfs_umount_scratch();
    }

    const auto partition_name = android::base::Basename(kScratchMountPoint);

    auto images = IImageManager::Open("remount", 10s);
    if (images && images->BackingImageExists(partition_name)) {
#if defined __ANDROID_RECOVERY__
        if (!images->DisableImage(partition_name)) {
            return false;
        }
#else
        if (!images->UnmapImageIfExists(partition_name) ||
            !images->DeleteBackingImage(partition_name)) {
            return false;
        }
#endif
    }

    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device)) return true;

    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        errno = save_errno;
        return true;
    }
    if (builder->FindPartition(partition_name) == nullptr) {
        errno = save_errno;
        return true;
    }
    builder->RemovePartition(partition_name);
    auto metadata = builder->Export();
    if (metadata && UpdatePartitionTable(super_device, *metadata.get(), slot_number)) {
        if (change) *change = true;
        if (!DestroyLogicalPartition(partition_name)) return false;
    } else {
        LERROR << "delete partition " << overlay;
        return false;
    }
    errno = save_errno;
    return true;
}

bool fs_mgr_overlayfs_teardown_one(const std::string& overlay, const std::string& mount_point,
                                   bool* change, bool* should_destroy_scratch = nullptr) {
    const auto top = overlay + kOverlayTopDir;

    if (!fs_mgr_access(top)) {
        if (should_destroy_scratch) *should_destroy_scratch = true;
        return true;
    }

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
    if (should_destroy_scratch) *should_destroy_scratch = cleanup_all;
    return ret;
}

bool fs_mgr_overlayfs_set_shared_mount(const std::string& mount_point, bool shared_flag) {
    auto ret = mount(nullptr, mount_point.c_str(), nullptr, shared_flag ? MS_SHARED : MS_PRIVATE,
                     nullptr);
    if (ret) {
        PERROR << "__mount(target=" << mount_point
               << ",flag=" << (shared_flag ? "MS_SHARED" : "MS_PRIVATE") << ")=" << ret;
        return false;
    }
    return true;
}

bool fs_mgr_overlayfs_move_mount(const std::string& source, const std::string& target) {
    auto ret = mount(source.c_str(), target.c_str(), nullptr, MS_MOVE, nullptr);
    if (ret) {
        PERROR << "__mount(source=" << source << ",target=" << target << ",flag=MS_MOVE)=" << ret;
        return false;
    }
    return true;
}

struct mount_info {
    std::string mount_point;
    bool shared_flag;
};

std::vector<mount_info> ReadMountinfoFromFile(const std::string& path) {
    std::vector<mount_info> info;

    auto file = std::unique_ptr<FILE, decltype(&fclose)>{fopen(path.c_str(), "re"), fclose};
    if (!file) {
        PERROR << __FUNCTION__ << "(): cannot open file: '" << path << "'";
        return info;
    }

    ssize_t len;
    size_t alloc_len = 0;
    char* line = nullptr;
    while ((len = getline(&line, &alloc_len, file.get())) != -1) {
        /* if the last character is a newline, shorten the string by 1 byte */
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }

        static constexpr char delim[] = " \t";
        char* save_ptr;
        if (!strtok_r(line, delim, &save_ptr)) {
            LERROR << "Error parsing mount ID";
            break;
        }
        if (!strtok_r(nullptr, delim, &save_ptr)) {
            LERROR << "Error parsing parent ID";
            break;
        }
        if (!strtok_r(nullptr, delim, &save_ptr)) {
            LERROR << "Error parsing mount source";
            break;
        }
        if (!strtok_r(nullptr, delim, &save_ptr)) {
            LERROR << "Error parsing root";
            break;
        }

        char* p;
        if (!(p = strtok_r(nullptr, delim, &save_ptr))) {
            LERROR << "Error parsing mount_point";
            break;
        }
        mount_info entry = {p, false};

        if (!strtok_r(nullptr, delim, &save_ptr)) {
            LERROR << "Error parsing mount_flags";
            break;
        }

        while ((p = strtok_r(nullptr, delim, &save_ptr))) {
            if ((p[0] == '-') && (p[1] == '\0')) break;
            if (android::base::StartsWith(p, "shared:")) entry.shared_flag = true;
        }
        if (!p) {
            LERROR << "Error parsing fields";
            break;
        }
        info.emplace_back(std::move(entry));
    }

    free(line);
    if (info.empty()) {
        LERROR << __FUNCTION__ << "(): failed to load mountinfo from : '" << path << "'";
    }
    return info;
}

bool fs_mgr_overlayfs_mount(const std::string& mount_point) {
    auto options = fs_mgr_get_overlayfs_options(mount_point);
    if (options.empty()) return false;

    auto retval = true;
    auto save_errno = errno;

    struct move_entry {
        std::string mount_point;
        std::string dir;
        bool shared_flag;
    };
    std::vector<move_entry> move;
    auto parent_private = false;
    auto parent_made_private = false;
    auto dev_private = false;
    auto dev_made_private = false;
    for (auto& entry : ReadMountinfoFromFile("/proc/self/mountinfo")) {
        if ((entry.mount_point == mount_point) && !entry.shared_flag) {
            parent_private = true;
        }
        if ((entry.mount_point == "/dev") && !entry.shared_flag) {
            dev_private = true;
        }

        if (!android::base::StartsWith(entry.mount_point, mount_point + "/")) {
            continue;
        }
        if (std::find_if(move.begin(), move.end(), [&entry](const auto& it) {
                return android::base::StartsWith(entry.mount_point, it.mount_point + "/");
            }) != move.end()) {
            continue;
        }

        // use as the bound directory in /dev.
        auto new_context = fs_mgr_get_context(entry.mount_point);
        if (!new_context.empty() && setfscreatecon(new_context.c_str())) {
            PERROR << "setfscreatecon " << new_context;
        }
        move_entry new_entry = {std::move(entry.mount_point), "/dev/TemporaryDir-XXXXXX",
                                entry.shared_flag};
        const auto target = mkdtemp(new_entry.dir.data());
        if (!target) {
            retval = false;
            save_errno = errno;
            PERROR << "temporary directory for MS_BIND";
            setfscreatecon(nullptr);
            continue;
        }
        setfscreatecon(nullptr);

        if (!parent_private && !parent_made_private) {
            parent_made_private = fs_mgr_overlayfs_set_shared_mount(mount_point, false);
        }
        if (new_entry.shared_flag) {
            new_entry.shared_flag = fs_mgr_overlayfs_set_shared_mount(new_entry.mount_point, false);
        }
        if (!fs_mgr_overlayfs_move_mount(new_entry.mount_point, new_entry.dir)) {
            retval = false;
            save_errno = errno;
            if (new_entry.shared_flag) {
                fs_mgr_overlayfs_set_shared_mount(new_entry.mount_point, true);
            }
            continue;
        }
        move.emplace_back(std::move(new_entry));
    }

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

    auto ret = mount("overlay", mount_point.c_str(), "overlay", MS_RDONLY | MS_NOATIME,
                     options.c_str());
    if (ret) {
        retval = false;
        save_errno = errno;
        PERROR << report << ret;
    } else {
        LINFO << report << ret;
    }

    // Move submounts back.
    for (const auto& entry : move) {
        if (!dev_private && !dev_made_private) {
            dev_made_private = fs_mgr_overlayfs_set_shared_mount("/dev", false);
        }

        if (!fs_mgr_overlayfs_move_mount(entry.dir, entry.mount_point)) {
            retval = false;
            save_errno = errno;
        } else if (entry.shared_flag &&
                   !fs_mgr_overlayfs_set_shared_mount(entry.mount_point, true)) {
            retval = false;
            save_errno = errno;
        }
        rmdir(entry.dir.c_str());
    }
    if (dev_made_private) {
        fs_mgr_overlayfs_set_shared_mount("/dev", true);
    }
    if (parent_made_private) {
        fs_mgr_overlayfs_set_shared_mount(mount_point, true);
    }

    errno = save_errno;
    return retval;
}

// Mount kScratchMountPoint
bool fs_mgr_overlayfs_mount_scratch(const std::string& device_path, const std::string mnt_type,
                                    bool readonly = false) {
    if (readonly) {
        if (!fs_mgr_access(device_path)) return false;
    } else {
        if (!fs_mgr_rw_access(device_path)) return false;
    }

    auto f2fs = fs_mgr_is_f2fs(device_path);
    auto ext4 = fs_mgr_is_ext4(device_path);
    if (!f2fs && !ext4) return false;

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
    if ((mnt_type == "f2fs") && !f2fs) entry.fs_type = "ext4";
    if ((mnt_type == "ext4") && !ext4) entry.fs_type = "f2fs";
    entry.flags = MS_NOATIME | MS_RDONLY;
    auto mounted = true;
    if (!readonly) {
        if (entry.fs_type == "ext4") {
            // check if ext4 de-dupe
            entry.flags |= MS_RDONLY;
            auto save_errno = errno;
            mounted = fs_mgr_do_mount_one(entry) == 0;
            if (mounted) {
                mounted = !fs_mgr_has_shared_blocks(entry.mount_point, entry.blk_device);
                fs_mgr_overlayfs_umount_scratch();
            }
            errno = save_errno;
        }
        entry.flags &= ~MS_RDONLY;
        fs_mgr_set_blk_ro(device_path, false);
    }
    entry.fs_mgr_flags.check = true;
    auto save_errno = errno;
    if (mounted) mounted = fs_mgr_do_mount_one(entry) == 0;
    if (!mounted) {
        if ((entry.fs_type == "f2fs") && ext4) {
            entry.fs_type = "ext4";
            mounted = fs_mgr_do_mount_one(entry) == 0;
        } else if ((entry.fs_type == "ext4") && f2fs) {
            entry.fs_type = "f2fs";
            mounted = fs_mgr_do_mount_one(entry) == 0;
        }
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

// Note: we do not check access() here except for the super partition, since
// in first-stage init we wouldn't have registed by-name symlinks for "other"
// partitions that won't be mounted.
static std::string GetPhysicalScratchDevice() {
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    auto path = fs_mgr_overlayfs_super_device(slot_number == 0);
    if (super_device != path) {
        return path;
    }
    if (fs_mgr_access(super_device)) {
        // Do not try to use system_other on a DAP device.
        return "";
    }

    auto other_slot = fs_mgr_get_other_slot_suffix();
    if (!other_slot.empty()) {
        return kPhysicalDevice + "system" + other_slot;
    }
    return "";
}

// Note: The scratch partition of DSU is managed by gsid, and should be initialized during
// first-stage-mount. Just check if the DM device for DSU scratch partition is created or not.
static std::string GetDsuScratchDevice() {
    auto& dm = DeviceMapper::Instance();
    std::string device;
    if (dm.GetState(android::gsi::kDsuScratch) != DmDeviceState::INVALID &&
        dm.GetDmDevicePathByName(android::gsi::kDsuScratch, &device)) {
        return device;
    }
    return "";
}

// This returns the scratch device that was detected during early boot (first-
// stage init). If the device was created later, for example during setup for
// the adb remount command, it can return an empty string since it does not
// query ImageManager. (Note that ImageManager in first-stage init will always
// use device-mapper, since /data is not available to use loop devices.)
static std::string GetBootScratchDevice() {
    // Note: fs_mgr_is_dsu_running() always returns false in recovery or fastbootd.
    if (fs_mgr_is_dsu_running()) {
        return GetDsuScratchDevice();
    }

    auto& dm = DeviceMapper::Instance();

    // If there is a scratch partition allocated in /data or on super, we
    // automatically prioritize that over super_other or system_other.
    // Some devices, for example, have a write-protected eMMC and the
    // super partition cannot be used even if it exists.
    std::string device;
    auto partition_name = android::base::Basename(kScratchMountPoint);
    if (dm.GetState(partition_name) != DmDeviceState::INVALID &&
        dm.GetDmDevicePathByName(partition_name, &device)) {
        return device;
    }

    // There is no dynamic scratch, so try and find a physical one.
    return GetPhysicalScratchDevice();
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
    command += " " + scratch_device + " >/dev/null 2>/dev/null </dev/null";
    fs_mgr_set_blk_ro(scratch_device, false);
    auto ret = system(command.c_str());
    if (ret) {
        LERROR << "make " << mnt_type << " filesystem on " << scratch_device << " return=" << ret;
        return false;
    }
    return true;
}

static void TruncatePartitionsWithSuffix(MetadataBuilder* builder, const std::string& suffix) {
    auto& dm = DeviceMapper::Instance();

    // Remove <other> partitions
    for (const auto& group : builder->ListGroups()) {
        for (const auto& part : builder->ListPartitionsInGroup(group)) {
            const auto& name = part->name();
            if (!android::base::EndsWith(name, suffix)) {
                continue;
            }
            if (dm.GetState(name) != DmDeviceState::INVALID && !DestroyLogicalPartition(name)) {
                continue;
            }
            builder->ResizePartition(builder->FindPartition(name), 0);
        }
    }
}

// Create or update a scratch partition within super.
static bool CreateDynamicScratch(std::string* scratch_device, bool* partition_exists,
                                 bool* change) {
    const auto partition_name = android::base::Basename(kScratchMountPoint);

    auto& dm = DeviceMapper::Instance();
    *partition_exists = dm.GetState(partition_name) != DmDeviceState::INVALID;

    auto partition_create = !*partition_exists;
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    auto builder = MetadataBuilder::New(super_device, slot_number);
    if (!builder) {
        LERROR << "open " << super_device << " metadata";
        return false;
    }
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
            if (builder->GetBlockDeviceInfo(fs_mgr_get_super_partition_name(slot_number), &info)) {
                margin_size = 3 * info.logical_block_size;
            }
            partition_size = std::max(std::min(kMinimumSize, partition_size - margin_size),
                                      partition_size / 2);
            if (partition_size > partition->size()) {
                if (!builder->ResizePartition(partition, partition_size)) {
                    // Try to free up space by deallocating partitions in the other slot.
                    TruncatePartitionsWithSuffix(builder.get(), fs_mgr_get_other_slot_suffix());

                    partition_size =
                            builder->AllocatableSpace() - builder->UsedSpace() + partition->size();
                    partition_size = std::max(std::min(kMinimumSize, partition_size - margin_size),
                                              partition_size / 2);
                    if (!builder->ResizePartition(partition, partition_size)) {
                        LERROR << "resize " << partition_name;
                        return false;
                    }
                }
                if (!partition_create) DestroyLogicalPartition(partition_name);
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
        CreateLogicalPartitionParams params = {
                .block_device = super_device,
                .metadata_slot = slot_number,
                .partition_name = partition_name,
                .force_writable = true,
                .timeout_ms = 10s,
        };
        if (!CreateLogicalPartition(params, scratch_device)) {
            return false;
        }

        if (change) *change = true;
    } else if (scratch_device->empty()) {
        *scratch_device = GetBootScratchDevice();
    }
    return true;
}

static bool CreateScratchOnData(std::string* scratch_device, bool* partition_exists, bool* change) {
    *partition_exists = false;
    if (change) *change = false;

    auto images = IImageManager::Open("remount", 10s);
    if (!images) {
        return false;
    }

    auto partition_name = android::base::Basename(kScratchMountPoint);
    if (images->GetMappedImageDevice(partition_name, scratch_device)) {
        *partition_exists = true;
        return true;
    }

    BlockDeviceInfo info;
    PartitionOpener opener;
    if (!opener.GetInfo(fs_mgr_get_super_partition_name(), &info)) {
        LERROR << "could not get block device info for super";
        return false;
    }

    if (change) *change = true;

    // Note: calling RemoveDisabledImages here ensures that we do not race with
    // clean_scratch_files and accidentally try to map an image that will be
    // deleted.
    if (!images->RemoveDisabledImages()) {
        return false;
    }
    if (!images->BackingImageExists(partition_name)) {
        static constexpr uint64_t kMinimumSize = 16_MiB;
        static constexpr uint64_t kMaximumSize = 2_GiB;

        uint64_t size = std::clamp(info.size / 2, kMinimumSize, kMaximumSize);
        auto flags = IImageManager::CREATE_IMAGE_DEFAULT;

        if (!images->CreateBackingImage(partition_name, size, flags)) {
            LERROR << "could not create scratch image of " << size << " bytes";
            return false;
        }
    }
    if (!images->MapImageDevice(partition_name, 10s, scratch_device)) {
        LERROR << "could not map scratch image";
        return false;
    }
    return true;
}

static bool CanUseSuperPartition(const Fstab& fstab, bool* is_virtual_ab) {
    auto slot_number = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(slot_number);
    if (!fs_mgr_rw_access(super_device) || !fs_mgr_overlayfs_has_logical(fstab)) {
        return false;
    }
    auto metadata = ReadMetadata(super_device, slot_number);
    if (!metadata) {
        return false;
    }
    *is_virtual_ab = !!(metadata->header.flags & LP_HEADER_FLAG_VIRTUAL_AB_DEVICE);
    return true;
}

bool fs_mgr_overlayfs_create_scratch(const Fstab& fstab, std::string* scratch_device,
                                     bool* partition_exists, bool* change) {
    // Use the DSU scratch device managed by gsid if within a DSU system.
    if (fs_mgr_is_dsu_running()) {
        *scratch_device = GetDsuScratchDevice();
        *partition_exists = !scratch_device->empty();
        *change = false;
        return *partition_exists;
    }

    // Try a physical partition first.
    *scratch_device = GetPhysicalScratchDevice();
    if (!scratch_device->empty() && fs_mgr_rw_access(*scratch_device)) {
        *partition_exists = true;
        return true;
    }

    // If that fails, see if we can land on super.
    bool is_virtual_ab;
    if (CanUseSuperPartition(fstab, &is_virtual_ab)) {
        bool can_use_data = false;
        if (is_virtual_ab && FilesystemHasReliablePinning("/data", &can_use_data) && can_use_data) {
            return CreateScratchOnData(scratch_device, partition_exists, change);
        }
        return CreateDynamicScratch(scratch_device, partition_exists, change);
    }

    errno = ENXIO;
    return false;
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

bool fs_mgr_overlayfs_invalid() {
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) return true;

    // in recovery or fastbootd, not allowed!
    return fs_mgr_in_recovery();
}

}  // namespace

Fstab fs_mgr_overlayfs_candidate_list(const Fstab& fstab) {
    Fstab candidates;
    for (const auto& entry : fstab) {
        FstabEntry new_entry = entry;
        if (!fs_mgr_overlayfs_already_mounted(entry.mount_point) &&
            !fs_mgr_wants_overlayfs(&new_entry)) {
            continue;
        }
        auto new_mount_point = fs_mgr_mount_point(entry.mount_point);
        auto duplicate_or_more_specific = false;
        for (auto it = candidates.begin(); it != candidates.end();) {
            auto it_mount_point = fs_mgr_mount_point(it->mount_point);
            if ((it_mount_point == new_mount_point) ||
                (android::base::StartsWith(new_mount_point, it_mount_point + "/"))) {
                duplicate_or_more_specific = true;
                break;
            }
            if (android::base::StartsWith(it_mount_point, new_mount_point + "/")) {
                it = candidates.erase(it);
            } else {
                ++it;
            }
        }
        if (!duplicate_or_more_specific) candidates.emplace_back(std::move(new_entry));
    }
    return candidates;
}

static void TryMountScratch() {
    // Note we get the boot scratch device here, which means if scratch was
    // just created through ImageManager, this could fail. In practice this
    // should not happen because "remount" detects this scenario (by checking
    // if verity is still disabled, i.e. no reboot occurred), and skips calling
    // fs_mgr_overlayfs_mount_all().
    auto scratch_device = GetBootScratchDevice();
    if (!fs_mgr_rw_access(scratch_device)) {
        return;
    }
    if (!WaitForFile(scratch_device, 10s)) {
        return;
    }
    const auto mount_type = fs_mgr_overlayfs_scratch_mount_type();
    if (!fs_mgr_overlayfs_mount_scratch(scratch_device, mount_type, true /* readonly */)) {
        return;
    }
    auto has_overlayfs_dir = fs_mgr_access(kScratchMountPoint + kOverlayTopDir);
    fs_mgr_overlayfs_umount_scratch();
    if (has_overlayfs_dir) {
        fs_mgr_overlayfs_mount_scratch(scratch_device, mount_type);
    }
}

bool fs_mgr_overlayfs_mount_all(Fstab* fstab) {
    auto ret = false;
    if (fs_mgr_overlayfs_invalid()) return ret;

    auto scratch_can_be_mounted = true;
    for (const auto& entry : fs_mgr_overlayfs_candidate_list(*fstab)) {
        if (fs_mgr_is_verity_enabled(entry)) continue;
        auto mount_point = fs_mgr_mount_point(entry.mount_point);
        if (fs_mgr_overlayfs_already_mounted(mount_point)) {
            ret = true;
            continue;
        }
        if (scratch_can_be_mounted) {
            scratch_can_be_mounted = false;
            TryMountScratch();
        }
        if (fs_mgr_overlayfs_mount(mount_point)) ret = true;
    }
    return ret;
}

// Returns false if setup not permitted, errno set to last error.
// If something is altered, set *change.
bool fs_mgr_overlayfs_setup(const char* backing, const char* mount_point, bool* change,
                            bool force) {
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
    auto candidates = fs_mgr_overlayfs_candidate_list(fstab);
    for (auto it = candidates.begin(); it != candidates.end();) {
        if (mount_point &&
            (fs_mgr_mount_point(it->mount_point) != fs_mgr_mount_point(mount_point))) {
            it = candidates.erase(it);
            continue;
        }
        save_errno = errno;
        auto verity_enabled = !force && fs_mgr_is_verity_enabled(*it);
        if (errno == ENOENT || errno == ENXIO) errno = save_errno;
        if (verity_enabled) {
            it = candidates.erase(it);
            continue;
        }
        ++it;
    }

    if (candidates.empty()) return ret;

    std::string dir;
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
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
    for (const auto& entry : candidates) {
        ret |= fs_mgr_overlayfs_setup_one(overlay, fs_mgr_mount_point(entry.mount_point), change);
    }
    return ret;
}

// Note: This function never returns the DSU scratch device in recovery or fastbootd,
// because the DSU scratch is created in the first-stage-mount, which is not run in recovery.
static bool EnsureScratchMapped(std::string* device, bool* mapped) {
    *mapped = false;
    *device = GetBootScratchDevice();
    if (!device->empty()) {
        return true;
    }

    if (!fs_mgr_in_recovery()) {
        errno = EINVAL;
        return false;
    }

    auto partition_name = android::base::Basename(kScratchMountPoint);

    // Check for scratch on /data first, before looking for a modified super
    // partition. We should only reach this code in recovery, because scratch
    // would otherwise always be mapped.
    auto images = IImageManager::Open("remount", 10s);
    if (images && images->BackingImageExists(partition_name)) {
        if (!images->MapImageDevice(partition_name, 10s, device)) {
            return false;
        }
        *mapped = true;
        return true;
    }

    // Avoid uart spam by first checking for a scratch partition.
    auto metadata_slot = fs_mgr_overlayfs_slot_number();
    auto super_device = fs_mgr_overlayfs_super_device(metadata_slot);
    auto metadata = ReadCurrentMetadata(super_device);
    if (!metadata) {
        return false;
    }

    auto partition = FindPartition(*metadata.get(), partition_name);
    if (!partition) {
        return false;
    }

    CreateLogicalPartitionParams params = {
            .block_device = super_device,
            .metadata = metadata.get(),
            .partition = partition,
            .force_writable = true,
            .timeout_ms = 10s,
    };
    if (!CreateLogicalPartition(params, device)) {
        return false;
    }
    *mapped = true;
    return true;
}

// This should only be reachable in recovery, where DSU scratch is not
// automatically mapped.
static bool MapDsuScratchDevice(std::string* device) {
    std::string dsu_slot;
    if (!android::gsi::IsGsiInstalled() || !android::gsi::GetActiveDsu(&dsu_slot) ||
        dsu_slot.empty()) {
        // Nothing to do if no DSU installation present.
        return false;
    }

    auto images = IImageManager::Open("dsu/" + dsu_slot, 10s);
    if (!images || !images->BackingImageExists(android::gsi::kDsuScratch)) {
        // Nothing to do if DSU scratch device doesn't exist.
        return false;
    }

    images->UnmapImageDevice(android::gsi::kDsuScratch);
    if (!images->MapImageDevice(android::gsi::kDsuScratch, 10s, device)) {
        return false;
    }
    return true;
}

// Returns false if teardown not permitted, errno set to last error.
// If something is altered, set *change.
bool fs_mgr_overlayfs_teardown(const char* mount_point, bool* change) {
    if (change) *change = false;
    auto ret = true;

    // If scratch exists, but is not mounted, lets gain access to clean
    // specific override entries.
    auto mount_scratch = false;
    if ((mount_point != nullptr) && !fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
        std::string scratch_device = GetBootScratchDevice();
        if (!scratch_device.empty()) {
            mount_scratch = fs_mgr_overlayfs_mount_scratch(scratch_device,
                                                           fs_mgr_overlayfs_scratch_mount_type());
        }
    }
    bool should_destroy_scratch = false;
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
        ret &= fs_mgr_overlayfs_teardown_one(
                overlay_mount_point, mount_point ? fs_mgr_mount_point(mount_point) : "", change,
                overlay_mount_point == kScratchMountPoint ? &should_destroy_scratch : nullptr);
    }
    // Do not attempt to destroy DSU scratch if within a DSU system,
    // because DSU scratch partition is managed by gsid.
    if (should_destroy_scratch && !fs_mgr_is_dsu_running()) {
        ret &= fs_mgr_overlayfs_teardown_scratch(kScratchMountPoint, change);
    }
    if (fs_mgr_overlayfs_valid() == OverlayfsValidResult::kNotSupported) {
        // After obligatory teardown to make sure everything is clean, but if
        // we didn't want overlayfs in the first place, we do not want to
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
    if (mount_scratch) {
        fs_mgr_overlayfs_umount_scratch();
    }
    return ret;
}

bool fs_mgr_overlayfs_is_setup() {
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) return true;
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return false;
    }
    if (fs_mgr_overlayfs_invalid()) return false;
    for (const auto& entry : fs_mgr_overlayfs_candidate_list(fstab)) {
        if (fs_mgr_is_verity_enabled(entry)) continue;
        if (fs_mgr_overlayfs_already_mounted(fs_mgr_mount_point(entry.mount_point))) return true;
    }
    return false;
}

namespace android {
namespace fs_mgr {

void MapScratchPartitionIfNeeded(Fstab* fstab,
                                 const std::function<bool(const std::set<std::string>&)>& init) {
    if (fs_mgr_overlayfs_invalid()) {
        return;
    }
    if (GetEntryForMountPoint(fstab, kScratchMountPoint) != nullptr) {
        return;
    }

    bool want_scratch = false;
    for (const auto& entry : fs_mgr_overlayfs_candidate_list(*fstab)) {
        if (fs_mgr_is_verity_enabled(entry)) {
            continue;
        }
        if (fs_mgr_overlayfs_already_mounted(fs_mgr_mount_point(entry.mount_point))) {
            continue;
        }
        want_scratch = true;
        break;
    }
    if (!want_scratch) {
        return;
    }

    if (ScratchIsOnData()) {
        if (auto images = IImageManager::Open("remount", 0ms)) {
            images->MapAllImages(init);
        }
    }

    // Physical or logical partitions will have already been mapped here,
    // so just ensure /dev/block symlinks exist.
    auto device = GetBootScratchDevice();
    if (!device.empty()) {
        init({android::base::Basename(device)});
    }
}

void CleanupOldScratchFiles() {
    if (!ScratchIsOnData()) {
        return;
    }
    if (auto images = IImageManager::Open("remount", 0ms)) {
        images->RemoveDisabledImages();
    }
}

void TeardownAllOverlayForMountPoint(const std::string& mount_point) {
    if (!fs_mgr_in_recovery()) {
        LERROR << __FUNCTION__ << "(): must be called within recovery.";
        return;
    }

    // Empty string means teardown everything.
    const std::string teardown_dir = mount_point.empty() ? "" : fs_mgr_mount_point(mount_point);
    constexpr bool* ignore_change = nullptr;

    // Teardown legacy overlay mount points that's not backed by a scratch device.
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
        if (overlay_mount_point == kScratchMountPoint) {
            continue;
        }
        fs_mgr_overlayfs_teardown_one(overlay_mount_point, teardown_dir, ignore_change);
    }

    // Map scratch device, mount kScratchMountPoint and teardown kScratchMountPoint.
    bool mapped = false;
    std::string scratch_device;
    if (EnsureScratchMapped(&scratch_device, &mapped)) {
        fs_mgr_overlayfs_umount_scratch();
        if (fs_mgr_overlayfs_mount_scratch(scratch_device, fs_mgr_overlayfs_scratch_mount_type())) {
            bool should_destroy_scratch = false;
            fs_mgr_overlayfs_teardown_one(kScratchMountPoint, teardown_dir, ignore_change,
                                          &should_destroy_scratch);
            if (should_destroy_scratch) {
                fs_mgr_overlayfs_teardown_scratch(kScratchMountPoint, nullptr);
            }
            fs_mgr_overlayfs_umount_scratch();
        }
        if (mapped) {
            DestroyLogicalPartition(android::base::Basename(kScratchMountPoint));
        }
    }

    // Teardown DSU overlay if present.
    if (MapDsuScratchDevice(&scratch_device)) {
        fs_mgr_overlayfs_umount_scratch();
        if (fs_mgr_overlayfs_mount_scratch(scratch_device, fs_mgr_overlayfs_scratch_mount_type())) {
            fs_mgr_overlayfs_teardown_one(kScratchMountPoint, teardown_dir, ignore_change);
            fs_mgr_overlayfs_umount_scratch();
        }
        DestroyLogicalPartition(android::gsi::kDsuScratch);
    }
}

}  // namespace fs_mgr
}  // namespace android

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
    if (minor > 3) {
        return OverlayfsValidResult::kNotSupported;
    }
    return OverlayfsValidResult::kOk;
}
