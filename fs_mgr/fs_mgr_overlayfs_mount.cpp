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

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <selinux/selinux.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <ext4_utils/ext4_utils.h>
#include <fs_mgr.h>
#include <fs_mgr/file_wait.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <libgsi/libgsi.h>
#include <storage_literals/storage_literals.h>

#include "fs_mgr_overlayfs_control.h"
#include "fs_mgr_overlayfs_mount.h"
#include "fs_mgr_priv.h"

using namespace std::literals;
using namespace android::fs_mgr;
using namespace android::storage_literals;

constexpr char kPreferCacheBackingStorageProp[] = "fs_mgr.overlayfs.prefer_cache_backing_storage";

constexpr char kCacheMountPoint[] = "/cache";
constexpr char kPhysicalDevice[] = "/dev/block/by-name/";

// Mount tree to temporarily hold references to submounts.
constexpr char kMoveMountTempDir[] = "/dev/remount";

constexpr char kLowerdirOption[] = "lowerdir=";
constexpr char kUpperdirOption[] = "upperdir=";
constexpr char kWorkdirOption[] = "workdir=";

bool fs_mgr_is_dsu_running() {
    // Since android::gsi::CanBootIntoGsi() or android::gsi::MarkSystemAsGsi() is
    // never called in recovery, the return value of android::gsi::IsGsiRunning()
    // is not well-defined. In this case, just return false as being in recovery
    // implies not running a DSU system.
    if (InRecovery()) return false;
    return android::gsi::IsGsiRunning();
}

std::vector<const std::string> OverlayMountPoints() {
    // Never fallback to legacy cache mount point if within a DSU system,
    // because running a DSU system implies the device supports dynamic
    // partitions, which means legacy cache mustn't be used.
    if (fs_mgr_is_dsu_running()) {
        return {kScratchMountPoint};
    }

    // For non-A/B devices prefer cache backing storage if
    // kPreferCacheBackingStorageProp property set.
    if (fs_mgr_get_slot_suffix().empty() &&
        android::base::GetBoolProperty(kPreferCacheBackingStorageProp, false) &&
        android::base::GetIntProperty("ro.vendor.api_level", -1) < __ANDROID_API_T__) {
        return {kCacheMountPoint, kScratchMountPoint};
    }

    return {kScratchMountPoint, kCacheMountPoint};
}

std::string GetEncodedBaseDirForMountPoint(const std::string& mount_point) {
    std::string normalized_path;
    if (mount_point.empty() || !android::base::Realpath(mount_point, &normalized_path)) {
        return "";
    }
    std::string_view sv(normalized_path);
    if (sv != "/") {
        android::base::ConsumePrefix(&sv, "/");
        android::base::ConsumeSuffix(&sv, "/");
    }
    return android::base::StringReplace(sv, "/", "@", true);
}

static bool fs_mgr_is_dir(const std::string& path) {
    struct stat st;
    return !stat(path.c_str(), &st) && S_ISDIR(st.st_mode);
}

// At less than 1% or 8MB of free space return value of false,
// means we will try to wrap with overlayfs.
bool fs_mgr_filesystem_has_space(const std::string& mount_point) {
    // If we have access issues to find out space remaining, return true
    // to prevent us trying to override with overlayfs.
    struct statvfs vst;
    if (statvfs(mount_point.c_str(), &vst)) {
        PLOG(ERROR) << "statvfs " << mount_point;
        return true;
    }

    static constexpr int kPercentThreshold = 1;                       // 1%
    static constexpr unsigned long kSizeThreshold = 8 * 1024 * 1024;  // 8MB

    return (vst.f_bfree >= (vst.f_blocks * kPercentThreshold / 100)) &&
           (static_cast<uint64_t>(vst.f_bfree) * vst.f_frsize) >= kSizeThreshold;
}

static bool fs_mgr_update_blk_device(FstabEntry* entry) {
    if (entry->fs_mgr_flags.logical) {
        fs_mgr_update_logical_partition(entry);
    }
    if (access(entry->blk_device.c_str(), F_OK) == 0) {
        return true;
    }
    if (entry->blk_device != "/dev/root") {
        return false;
    }

    // special case for system-as-root (taimen and others)
    auto blk_device = kPhysicalDevice + "system"s;
    if (access(blk_device.c_str(), F_OK)) {
        blk_device += fs_mgr_get_slot_suffix();
        if (access(blk_device.c_str(), F_OK)) {
            return false;
        }
    }
    entry->blk_device = blk_device;
    return true;
}

static bool fs_mgr_has_shared_blocks(const std::string& mount_point, const std::string& dev) {
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

#define F2FS_SUPER_OFFSET 1024
#define F2FS_FEATURE_OFFSET 2180
#define F2FS_FEATURE_RO 0x4000
static bool fs_mgr_is_read_only_f2fs(const std::string& dev) {
    if (!fs_mgr_is_f2fs(dev)) return false;

    android::base::unique_fd fd(open(dev.c_str(), O_RDONLY | O_CLOEXEC));
    if (fd < 0) return false;

    __le32 feat;
    if ((TEMP_FAILURE_RETRY(lseek64(fd, F2FS_SUPER_OFFSET + F2FS_FEATURE_OFFSET, SEEK_SET)) < 0) ||
        (TEMP_FAILURE_RETRY(read(fd, &feat, sizeof(feat))) < 0)) {
        return false;
    }

    return (feat & cpu_to_le32(F2FS_FEATURE_RO)) != 0;
}

static bool fs_mgr_overlayfs_enabled(FstabEntry* entry) {
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

    // f2fs read-only mode doesn't support remount,rw
    if (fs_mgr_is_read_only_f2fs(entry->blk_device)) {
        return true;
    }

    // check if ext4 de-dupe
    auto has_shared_blocks = fs_mgr_has_shared_blocks(entry->mount_point, entry->blk_device);
    if (!has_shared_blocks && (entry->mount_point == "/system")) {
        has_shared_blocks = fs_mgr_has_shared_blocks("/", entry->blk_device);
    }
    return has_shared_blocks;
}

const std::string fs_mgr_mount_point(const std::string& mount_point) {
    if ("/"s != mount_point) return mount_point;
    return "/system";
}

// default options for mount_point, returns empty string for none available.
static std::string fs_mgr_get_overlayfs_options(const FstabEntry& entry) {
    const auto mount_point = fs_mgr_mount_point(entry.mount_point);
    if (!fs_mgr_is_dir(mount_point)) {
        return "";
    }
    const auto base = GetEncodedBaseDirForMountPoint(mount_point);
    if (base.empty()) {
        return "";
    }
    for (const auto& overlay_mount_point : OverlayMountPoints()) {
        const auto dir = overlay_mount_point + "/" + kOverlayTopDir + "/" + base + "/";
        const auto upper = dir + kUpperName;
        const auto work = dir + kWorkName;
        if (!fs_mgr_is_dir(upper) || !fs_mgr_is_dir(work) || access(work.c_str(), R_OK | W_OK)) {
            continue;
        }
        auto ret = kLowerdirOption + mount_point + "," + kUpperdirOption + upper + "," +
                   kWorkdirOption + work + android::fs_mgr::CheckOverlayfs().mount_flags;
        for (const auto& flag : android::base::Split(entry.fs_options, ",")) {
            if (android::base::StartsWith(flag, "context=")) {
                ret += "," + flag;
            }
        }
        return ret;
    }
    return "";
}

bool AutoSetFsCreateCon::Set(const std::string& context) {
    if (setfscreatecon(context.c_str())) {
        PLOG(ERROR) << "setfscreatecon " << context;
        return false;
    }
    ok_ = true;
    return true;
}

bool AutoSetFsCreateCon::Restore() {
    if (restored_ || !ok_) {
        return true;
    }
    if (setfscreatecon(nullptr)) {
        PLOG(ERROR) << "setfscreatecon null";
        return false;
    }
    restored_ = true;
    return true;
}

// Returns true if immediate unmount succeeded and the scratch mount point was
// removed.
bool fs_mgr_overlayfs_umount_scratch() {
    if (umount(kScratchMountPoint) != 0) {
        return false;
    }
    if (rmdir(kScratchMountPoint) != 0 && errno != ENOENT) {
        PLOG(ERROR) << "rmdir " << kScratchMountPoint;
    }
    return true;
}

static bool fs_mgr_overlayfs_set_shared_mount(const std::string& mount_point, bool shared_flag) {
    auto ret = mount(nullptr, mount_point.c_str(), nullptr, shared_flag ? MS_SHARED : MS_PRIVATE,
                     nullptr);
    if (ret) {
        PERROR << "__mount(target=" << mount_point
               << ",flag=" << (shared_flag ? "MS_SHARED" : "MS_PRIVATE") << ")=" << ret;
        return false;
    }
    return true;
}

static bool fs_mgr_overlayfs_move_mount(const std::string& source, const std::string& target) {
    auto ret = mount(source.c_str(), target.c_str(), nullptr, MS_MOVE, nullptr);
    if (ret) {
        PERROR << "__mount(source=" << source << ",target=" << target << ",flag=MS_MOVE)=" << ret;
        return false;
    }
    return true;
}

static bool fs_mgr_overlayfs_mount(const std::string& mount_point, const std::string& options) {
    auto report = "__mount(source=overlay,target="s + mount_point + ",type=overlay";
    for (const auto& opt : android::base::Split(options, ",")) {
        if (android::base::StartsWith(opt, kUpperdirOption)) {
            report = report + "," + opt;
            break;
        }
    }
    report = report + ")=";
    auto ret = mount("overlay", mount_point.c_str(), "overlay", MS_RDONLY | MS_NOATIME,
                     options.c_str());
    if (ret) {
        PERROR << report << ret;
    } else {
        LINFO << report << ret;
    }
    return !ret;
}

struct mount_info {
    std::string mount_point;
    bool shared_flag;
};

static std::vector<mount_info> ReadMountinfoFromFile(const std::string& path) {
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

static bool fs_mgr_overlayfs_mount_one(const FstabEntry& fstab_entry) {
    const auto mount_point = fs_mgr_mount_point(fstab_entry.mount_point);
    const auto options = fs_mgr_get_overlayfs_options(fstab_entry);
    if (options.empty()) return false;

    struct MoveEntry {
        std::string mount_point;
        std::string dir;
        bool shared_flag;
    };
    std::vector<MoveEntry> moved_mounts;

    bool retval = true;
    bool move_dir_shared = true;
    bool parent_shared = true;
    bool root_shared = true;
    bool root_made_private = false;

    // There could be multiple mount entries with the same mountpoint.
    // Group these entries together with stable_sort, and keep only the last entry of a group.
    // Only move mount the last entry in an over mount group, because the other entries are
    // overshadowed and only the filesystem mounted with the last entry participates in file
    // pathname resolution.
    auto mountinfo = ReadMountinfoFromFile("/proc/self/mountinfo");
    std::stable_sort(mountinfo.begin(), mountinfo.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.mount_point < rhs.mount_point;
    });
    std::reverse(mountinfo.begin(), mountinfo.end());
    auto erase_from = std::unique(
            mountinfo.begin(), mountinfo.end(),
            [](const auto& lhs, const auto& rhs) { return lhs.mount_point == rhs.mount_point; });
    mountinfo.erase(erase_from, mountinfo.end());
    std::reverse(mountinfo.begin(), mountinfo.end());
    // mountinfo is reversed twice, so still is in lexical sorted order.

    for (const auto& entry : mountinfo) {
        if (entry.mount_point == kMoveMountTempDir) {
            move_dir_shared = entry.shared_flag;
        }
        if (entry.mount_point == mount_point ||
            (mount_point == "/system" && entry.mount_point == "/")) {
            parent_shared = entry.shared_flag;
        }
        if (entry.mount_point == "/") {
            root_shared = entry.shared_flag;
        }
    }

    // Precondition is that kMoveMountTempDir is MS_PRIVATE, otherwise don't try to move any
    // submount in to or out of it.
    if (move_dir_shared) {
        mountinfo.clear();
    }

    // Need to make the original mountpoint MS_PRIVATE, so that the overlayfs can be MS_MOVE.
    // This could happen if its parent mount is remounted later.
    if (!fs_mgr_overlayfs_set_shared_mount(mount_point, false)) {
        // If failed to set "/system" mount type, it might be due to "/system" not being a valid
        // mountpoint after switch root. Retry with "/" in this case.
        if (errno == EINVAL && mount_point == "/system") {
            root_made_private = fs_mgr_overlayfs_set_shared_mount("/", false);
        }
    }

    for (const auto& entry : mountinfo) {
        // Find all immediate submounts.
        if (!android::base::StartsWith(entry.mount_point, mount_point + "/")) {
            continue;
        }
        // Exclude duplicated or more specific entries.
        if (std::find_if(moved_mounts.begin(), moved_mounts.end(), [&entry](const auto& it) {
                return it.mount_point == entry.mount_point ||
                       android::base::StartsWith(entry.mount_point, it.mount_point + "/");
            }) != moved_mounts.end()) {
            continue;
        }
        // mountinfo is in lexical order, so no need to worry about |entry| being a parent mount of
        // entries of |moved_mounts|.

        MoveEntry new_entry{entry.mount_point, kMoveMountTempDir + "/TemporaryDir-XXXXXX"s,
                            entry.shared_flag};
        {
            AutoSetFsCreateCon createcon;
            auto new_context = fs_mgr_get_context(entry.mount_point);
            if (new_context.empty() || !createcon.Set(new_context)) {
                continue;
            }
            const auto target = mkdtemp(new_entry.dir.data());
            if (!target) {
                retval = false;
                PERROR << "temporary directory for MS_MOVE";
                continue;
            }
            if (!createcon.Restore()) {
                retval = false;
                rmdir(new_entry.dir.c_str());
                continue;
            }
        }

        if (new_entry.shared_flag) {
            new_entry.shared_flag = fs_mgr_overlayfs_set_shared_mount(new_entry.mount_point, false);
        }
        if (!fs_mgr_overlayfs_move_mount(new_entry.mount_point, new_entry.dir)) {
            retval = false;
            if (new_entry.shared_flag) {
                fs_mgr_overlayfs_set_shared_mount(new_entry.mount_point, true);
            }
            rmdir(new_entry.dir.c_str());
            continue;
        }
        moved_mounts.push_back(std::move(new_entry));
    }

    retval &= fs_mgr_overlayfs_mount(mount_point, options);

    // Move submounts back.
    for (const auto& entry : moved_mounts) {
        if (!fs_mgr_overlayfs_move_mount(entry.dir, entry.mount_point)) {
            retval = false;
        } else if (entry.shared_flag &&
                   !fs_mgr_overlayfs_set_shared_mount(entry.mount_point, true)) {
            retval = false;
        }
        rmdir(entry.dir.c_str());
    }
    // If the original (overridden) mount was MS_SHARED, then set the overlayfs mount to MS_SHARED.
    if (parent_shared) {
        fs_mgr_overlayfs_set_shared_mount(mount_point, true);
    }
    if (root_shared && root_made_private) {
        fs_mgr_overlayfs_set_shared_mount("/", true);
    }

    return retval;
}

// Mount kScratchMountPoint
bool MountScratch(const std::string& device_path, bool readonly) {
    if (readonly) {
        if (access(device_path.c_str(), F_OK)) {
            LOG(ERROR) << "Path does not exist: " << device_path;
            return false;
        }
    } else if (access(device_path.c_str(), R_OK | W_OK)) {
        LOG(ERROR) << "Path does not exist or is not readwrite: " << device_path;
        return false;
    }

    std::vector<const char*> filesystem_candidates;
    if (fs_mgr_is_f2fs(device_path)) {
        filesystem_candidates = {"f2fs", "ext4"};
    } else if (fs_mgr_is_ext4(device_path)) {
        filesystem_candidates = {"ext4", "f2fs"};
    } else {
        LOG(ERROR) << "Scratch partition is not f2fs or ext4";
        return false;
    }

    AutoSetFsCreateCon createcon(kOverlayfsFileContext);
    if (!createcon.Ok()) {
        return false;
    }
    if (mkdir(kScratchMountPoint, 0755) && (errno != EEXIST)) {
        PERROR << "create " << kScratchMountPoint;
        return false;
    }

    FstabEntry entry;
    entry.blk_device = device_path;
    entry.mount_point = kScratchMountPoint;
    entry.flags = MS_NOATIME | MS_RDONLY;
    if (!readonly) {
        entry.flags &= ~MS_RDONLY;
        entry.flags |= MS_SYNCHRONOUS;
        entry.fs_options = "nodiscard";
        fs_mgr_set_blk_ro(device_path, false);
    }
    // check_fs requires apex runtime library
    if (fs_mgr_overlayfs_already_mounted("/data", false)) {
        entry.fs_mgr_flags.check = true;
    }
    bool mounted = false;
    for (auto fs_type : filesystem_candidates) {
        entry.fs_type = fs_type;
        if (fs_mgr_do_mount_one(entry) == 0) {
            mounted = true;
            break;
        }
    }
    if (!createcon.Restore()) {
        return false;
    }
    if (!mounted) {
        rmdir(kScratchMountPoint);
        return false;
    }
    return true;
}

// NOTE: OverlayfsSetupAllowed() must be "stricter" than OverlayfsTeardownAllowed().
// Setup is allowed only if teardown is also allowed.
bool OverlayfsSetupAllowed(bool verbose) {
    if (!kAllowOverlayfs) {
        if (verbose) {
            LOG(ERROR) << "Overlayfs remounts can only be used in debuggable builds";
        }
        return false;
    }
    // Check mandatory kernel patches.
    if (!android::fs_mgr::CheckOverlayfs().supported) {
        if (verbose) {
            LOG(ERROR) << "Kernel does not support overlayfs";
        }
        return false;
    }
    // in recovery or fastbootd, not allowed!
    if (InRecovery()) {
        if (verbose) {
            LOG(ERROR) << "Unsupported overlayfs setup from recovery";
        }
        return false;
    }
    return true;
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

Fstab fs_mgr_overlayfs_candidate_list(const Fstab& fstab) {
    android::fs_mgr::Fstab mounts;
    if (!android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts)) {
        PLOG(ERROR) << "Failed to read /proc/mounts";
        return {};
    }

    Fstab candidates;
    for (const auto& entry : fstab) {
        // Filter out partitions whose type doesn't match what's mounted.
        // This avoids spammy behavior on devices which can mount different
        // filesystems for each partition.
        auto proc_mount_point = (entry.mount_point == "/system") ? "/" : entry.mount_point;
        auto mounted = GetEntryForMountPoint(&mounts, proc_mount_point);
        if (!mounted || mounted->fs_type != entry.fs_type) {
            continue;
        }

        FstabEntry new_entry = entry;
        if (!fs_mgr_overlayfs_already_mounted(entry.mount_point) &&
            !fs_mgr_wants_overlayfs(&new_entry)) {
            continue;
        }
        const auto new_mount_point = fs_mgr_mount_point(new_entry.mount_point);
        if (std::find_if(candidates.begin(), candidates.end(), [&](const auto& it) {
                return fs_mgr_mount_point(it.mount_point) == new_mount_point;
            }) != candidates.end()) {
            continue;
        }
        candidates.push_back(std::move(new_entry));
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
    if (access(scratch_device.c_str(), R_OK | W_OK)) {
        return;
    }
    if (!WaitForFile(scratch_device, 10s)) {
        return;
    }
    if (!MountScratch(scratch_device, true /* readonly */)) {
        return;
    }
    const auto top = kScratchMountPoint + "/"s + kOverlayTopDir;
    const bool has_overlayfs_dir = access(top.c_str(), F_OK) == 0;
    fs_mgr_overlayfs_umount_scratch();
    if (has_overlayfs_dir) {
        MountScratch(scratch_device);
    }
}

bool fs_mgr_overlayfs_mount_all(Fstab* fstab) {
    if (!OverlayfsSetupAllowed()) {
        return false;
    }

    // Ensure kMoveMountTempDir is standalone mount tree with 'private' propagation by bind mounting
    // to itself and set to MS_PRIVATE.
    // Otherwise mounts moved in to it would have their propagation type changed unintentionally.
    // Section 5d, https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt
    if (!fs_mgr_overlayfs_already_mounted(kMoveMountTempDir, false)) {
        if (mkdir(kMoveMountTempDir, 0755) && errno != EEXIST) {
            PERROR << "mkdir " << kMoveMountTempDir;
        }
        if (mount(kMoveMountTempDir, kMoveMountTempDir, nullptr, MS_BIND, nullptr)) {
            PERROR << "bind mount " << kMoveMountTempDir;
        }
    }
    fs_mgr_overlayfs_set_shared_mount(kMoveMountTempDir, false);
    android::base::ScopeGuard umountDir([]() {
        umount(kMoveMountTempDir);
        rmdir(kMoveMountTempDir);
    });

    auto ret = true;
    auto scratch_can_be_mounted = !fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false);
    for (const auto& entry : fs_mgr_overlayfs_candidate_list(*fstab)) {
        if (fs_mgr_is_verity_enabled(entry)) continue;
        auto mount_point = fs_mgr_mount_point(entry.mount_point);
        if (fs_mgr_overlayfs_already_mounted(mount_point)) {
            continue;
        }
        if (scratch_can_be_mounted) {
            scratch_can_be_mounted = false;
            TryMountScratch();
        }
        ret &= fs_mgr_overlayfs_mount_one(entry);
    }
    return ret;
}

bool fs_mgr_overlayfs_is_setup() {
    if (!OverlayfsSetupAllowed()) {
        return false;
    }
    if (fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) return true;
    Fstab fstab;
    if (!ReadDefaultFstab(&fstab)) {
        return false;
    }
    for (const auto& entry : fs_mgr_overlayfs_candidate_list(fstab)) {
        if (fs_mgr_is_verity_enabled(entry)) continue;
        if (fs_mgr_overlayfs_already_mounted(fs_mgr_mount_point(entry.mount_point))) return true;
    }
    return false;
}

bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point, bool overlay_only) {
    Fstab fstab;
    if (!ReadFstabFromProcMounts(&fstab)) {
        return false;
    }
    const auto lowerdir = kLowerdirOption + mount_point;
    for (const auto& entry : GetEntriesForMountPoint(&fstab, mount_point)) {
        if (!overlay_only) {
            return true;
        }
        if (entry->fs_type != "overlay" && entry->fs_type != "overlayfs") {
            continue;
        }
        const auto options = android::base::Split(entry->fs_options, ",");
        for (const auto& opt : options) {
            if (opt == lowerdir) {
                return true;
            }
        }
    }
    return false;
}

namespace android {
namespace fs_mgr {

void MountOverlayfs(const FstabEntry& fstab_entry, bool* scratch_can_be_mounted) {
    if (!OverlayfsSetupAllowed()) {
        return;
    }
    const auto candidates = fs_mgr_overlayfs_candidate_list({fstab_entry});
    if (candidates.empty()) {
        return;
    }
    const auto& entry = candidates.front();
    if (fs_mgr_is_verity_enabled(entry)) {
        return;
    }
    const auto mount_point = fs_mgr_mount_point(entry.mount_point);
    if (fs_mgr_overlayfs_already_mounted(mount_point)) {
        return;
    }
    if (*scratch_can_be_mounted) {
        *scratch_can_be_mounted = false;
        if (!fs_mgr_overlayfs_already_mounted(kScratchMountPoint, false)) {
            TryMountScratch();
        }
    }
    const auto options = fs_mgr_get_overlayfs_options(entry);
    if (options.empty()) {
        return;
    }
    fs_mgr_overlayfs_mount(mount_point, options);
}

}  // namespace fs_mgr
}  // namespace android
