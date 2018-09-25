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
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

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
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>

#include "fs_mgr_priv.h"

using namespace std::literals;

#if ALLOW_ADBD_DISABLE_VERITY == 0  // If we are a user build, provide stubs

bool fs_mgr_overlayfs_mount_all(const fstab*) {
    return false;
}

bool fs_mgr_overlayfs_setup(const char*, const char*, bool* change) {
    if (change) *change = false;
    return false;
}

bool fs_mgr_overlayfs_teardown(const char*, bool* change) {
    if (change) *change = false;
    return false;
}

#else  // ALLOW_ADBD_DISABLE_VERITY == 0

namespace {

// acceptable overlayfs backing storage
const auto kOverlayMountPoint = "/cache"s;

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

std::string fs_mgr_get_context(const std::string& mount_point) {
    char* ctx = nullptr;
    auto len = getfilecon(mount_point.c_str(), &ctx);
    if ((len > 0) && ctx) {
        std::string context(ctx, len);
        free(ctx);
        return context;
    }
    return "";
}

// At less than 1% free space return value of false,
// means we will try to wrap with overlayfs.
bool fs_mgr_filesystem_has_space(const char* mount_point) {
    // If we have access issues to find out space remaining, return true
    // to prevent us trying to override with overlayfs.
    struct statvfs vst;
    if (statvfs(mount_point, &vst)) return true;

    static constexpr int kPercentThreshold = 1;  // 1%

    return (vst.f_bfree >= (vst.f_blocks * kPercentThreshold / 100));
}

bool fs_mgr_overlayfs_enabled(const struct fstab_rec* fsrec) {
    // readonly filesystem, can not be mount -o remount,rw
    // if squashfs or if free space is (near) zero making such a remount
    // virtually useless, or if there are shared blocks that prevent remount,rw
    return ("squashfs"s == fsrec->fs_type) ||
           fs_mgr_has_shared_blocks(fsrec->mount_point, fsrec->blk_device) ||
           !fs_mgr_filesystem_has_space(fsrec->mount_point);
}

const auto kUpperName = "upper"s;
const auto kWorkName = "work"s;
const auto kOverlayTopDir = "/overlay"s;

std::string fs_mgr_get_overlayfs_candidate(const std::string& mount_point) {
    if (!fs_mgr_is_dir(mount_point)) return "";
    auto dir =
            kOverlayMountPoint + kOverlayTopDir + "/" + android::base::Basename(mount_point) + "/";
    auto upper = dir + kUpperName;
    if (!fs_mgr_is_dir(upper)) return "";
    auto work = dir + kWorkName;
    if (!fs_mgr_is_dir(work)) return "";
    if (!fs_mgr_dir_is_writable(work)) return "";
    return dir;
}

const auto kLowerdirOption = "lowerdir="s;
const auto kUpperdirOption = "upperdir="s;

// default options for mount_point, returns empty string for none available.
std::string fs_mgr_get_overlayfs_options(const std::string& mount_point) {
    auto candidate = fs_mgr_get_overlayfs_candidate(mount_point);
    if (candidate.empty()) return "";

    auto context = fs_mgr_get_context(mount_point);
    if (!context.empty()) context = ",rootcontext="s + context;
    return "override_creds=off,"s + kLowerdirOption + mount_point + "," + kUpperdirOption +
           candidate + kUpperName + ",workdir=" + candidate + kWorkName + context;
}

bool fs_mgr_system_root_image(const fstab* fstab) {
    if (!fstab) {  // can not happen?
        // This will return empty on init first_stage_mount,
        // hence why we prefer checking the fstab instead.
        return android::base::GetBoolProperty("ro.build.system_root_image", false);
    }
    for (auto i = 0; i < fstab->num_entries; i++) {
        const auto fsrec = &fstab->recs[i];
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if ("/system"s == fsrec_mount_point) return false;
    }
    return true;
}

const char* fs_mgr_mount_point(const fstab* fstab, const char* mount_point) {
    if (!mount_point) return mount_point;
    if ("/"s != mount_point) return mount_point;
    if (!fs_mgr_system_root_image(fstab)) return mount_point;
    return "/system";
}

// return true if system supports overlayfs
bool fs_mgr_wants_overlayfs() {
    // This will return empty on init first_stage_mount, so speculative
    // determination, empty (unset) _or_ "1" is true which differs from the
    // official ro.debuggable policy.  ALLOW_ADBD_DISABLE_VERITY == 0 should
    // protect us from false in any case, so this is insurance.
    auto debuggable = android::base::GetProperty("ro.debuggable", "1");
    if (debuggable != "1") return false;

    // Overlayfs available in the kernel, and patched for override_creds?
    static signed char overlayfs_in_kernel = -1;  // cache for constant condition
    if (overlayfs_in_kernel == -1) {
        auto save_errno = errno;
        overlayfs_in_kernel = !access("/sys/module/overlay/parameters/override_creds", F_OK);
        errno = save_errno;
    }
    return overlayfs_in_kernel;
}

bool fs_mgr_overlayfs_already_mounted(const std::string& mount_point) {
    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab("/proc/mounts"),
                                                               fs_mgr_free_fstab);
    if (!fstab) return false;
    const auto lowerdir = kLowerdirOption + mount_point;
    for (auto i = 0; i < fstab->num_entries; ++i) {
        const auto fsrec = &fstab->recs[i];
        const auto fs_type = fsrec->fs_type;
        if (!fs_type) continue;
        if (("overlay"s != fs_type) && ("overlayfs"s != fs_type)) continue;
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if (mount_point != fsrec_mount_point) continue;
        const auto fs_options = fsrec->fs_options;
        if (!fs_options) continue;
        const auto options = android::base::Split(fs_options, ",");
        for (const auto& opt : options) {
            if (opt == lowerdir) {
                return true;
            }
        }
    }
    return false;
}

bool fs_mgr_overlayfs_verity_enabled(const std::string& basename_mount_point) {
    auto found = false;
    fs_mgr_update_verity_state(
            [&basename_mount_point, &found](fstab_rec*, const char* mount_point, int, int) {
                if (mount_point && (basename_mount_point == mount_point)) found = true;
            });
    return found;
}

bool fs_mgr_wants_overlayfs(const fstab_rec* fsrec) {
    if (!fsrec) return false;

    auto fsrec_mount_point = fsrec->mount_point;
    if (!fsrec_mount_point || !fsrec_mount_point[0]) return false;
    if (!fsrec->blk_device) return false;

    if (!fsrec->fs_type) return false;

    // Don't check entries that are managed by vold.
    if (fsrec->fs_mgr_flags & (MF_VOLDMANAGED | MF_RECOVERYONLY)) return false;

    // Only concerned with readonly partitions.
    if (!(fsrec->flags & MS_RDONLY)) return false;

    // If unbindable, do not allow overlayfs as this could expose us to
    // security issues.  On Android, this could also be used to turn off
    // the ability to overlay an otherwise acceptable filesystem since
    // /system and /vendor are never bound(sic) to.
    if (fsrec->flags & MS_UNBINDABLE) return false;

    if (!fs_mgr_overlayfs_enabled(fsrec)) return false;

    return !fs_mgr_overlayfs_verity_enabled(android::base::Basename(fsrec_mount_point));
}

bool fs_mgr_rm_all(const std::string& path, bool* change = nullptr) {
    auto save_errno = errno;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        if (errno == ENOENT) {
            errno = save_errno;
            return true;
        }
        PERROR << "opendir " << path;
        return false;
    }
    dirent* entry;
    auto ret = true;
    while ((entry = readdir(dir.get()))) {
        if (("."s == entry->d_name) || (".."s == entry->d_name)) continue;
        auto file = path + "/" + entry->d_name;
        if (entry->d_type == DT_UNKNOWN) {
            struct stat st;
            if (!lstat(file.c_str(), &st) && (st.st_mode & S_IFDIR)) entry->d_type = DT_DIR;
        }
        if (entry->d_type == DT_DIR) {
            ret &= fs_mgr_rm_all(file, change);
            if (!rmdir(file.c_str())) {
                if (change) *change = true;
            } else {
                ret = false;
                PERROR << "rmdir " << file;
            }
            continue;
        }
        if (!unlink(file.c_str())) {
            if (change) *change = true;
        } else {
            ret = false;
            PERROR << "rm " << file;
        }
    }
    return ret;
}

constexpr char kOverlayfsFileContext[] = "u:object_r:overlayfs_file:s0";

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

bool fs_mgr_overlayfs_mount(const std::string& mount_point) {
    auto options = fs_mgr_get_overlayfs_options(mount_point);
    if (options.empty()) return false;

    // hijack __mount() report format to help triage
    auto report = "__mount(source=overlay,target="s + mount_point + ",type=overlay";
    const auto opt_list = android::base::Split(options, ",");
    for (const auto opt : opt_list) {
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

std::vector<std::string> fs_mgr_candidate_list(const fstab* fstab,
                                               const char* mount_point = nullptr) {
    std::vector<std::string> mounts;
    if (!fstab) return mounts;

    for (auto i = 0; i < fstab->num_entries; i++) {
        const auto fsrec = &fstab->recs[i];
        if (!fs_mgr_wants_overlayfs(fsrec)) continue;
        std::string new_mount_point(fs_mgr_mount_point(fstab, fsrec->mount_point));
        if (mount_point && (new_mount_point != mount_point)) continue;
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
    // if not itemized /system or /, system as root, fake up
    // fs_mgr_wants_overlayfs evaluation of /system as candidate.

    if ((std::find(mounts.begin(), mounts.end(), "/system") == mounts.end()) &&
        !fs_mgr_get_entry_for_mount_point(const_cast<struct fstab*>(fstab), "/") &&
        !fs_mgr_get_entry_for_mount_point(const_cast<struct fstab*>(fstab), "/system") &&
        !fs_mgr_overlayfs_verity_enabled("system")) {
        mounts.emplace_back("/system");
    }
    return mounts;
}

}  // namespace

bool fs_mgr_overlayfs_mount_all(const fstab* fstab) {
    auto ret = false;

    if (!fs_mgr_wants_overlayfs()) return ret;

    if (!fstab) return ret;

    for (const auto& mount_point : fs_mgr_candidate_list(fstab)) {
        if (fs_mgr_overlayfs_already_mounted(mount_point)) continue;
        if (fs_mgr_overlayfs_mount(mount_point)) ret = true;
    }
    return ret;
}

// Returns false if setup not permitted, errno set to last error.
// If something is altered, set *change.
bool fs_mgr_overlayfs_setup(const char* backing, const char* mount_point, bool* change) {
    if (change) *change = false;
    auto ret = false;
    if (backing && (kOverlayMountPoint != backing)) {
        errno = EINVAL;
        return ret;
    }
    if (!fs_mgr_wants_overlayfs()) return ret;
    if (!fs_mgr_boot_completed()) {
        errno = EBUSY;
        PERROR << "setup";
        return ret;
    }

    std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                               fs_mgr_free_fstab);
    if (fstab && !fs_mgr_get_entry_for_mount_point(fstab.get(), kOverlayMountPoint)) return ret;
    auto mounts = fs_mgr_candidate_list(fstab.get(), fs_mgr_mount_point(fstab.get(), mount_point));
    if (fstab && mounts.empty()) return ret;

    if (setfscreatecon(kOverlayfsFileContext)) {
        PERROR << "setfscreatecon " << kOverlayfsFileContext;
    }
    auto overlay = kOverlayMountPoint + kOverlayTopDir;
    auto save_errno = errno;
    if (!mkdir(overlay.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        PERROR << "mkdir " << overlay;
    } else {
        errno = save_errno;
    }
    setfscreatecon(nullptr);
    if (!fstab && mount_point && fs_mgr_overlayfs_setup_one(overlay, mount_point, change)) {
        ret = true;
    }
    for (const auto& fsrec_mount_point : mounts) {
        ret |= fs_mgr_overlayfs_setup_one(overlay, fsrec_mount_point, change);
    }
    return ret;
}

// Returns false if teardown not permitted, errno set to last error.
// If something is altered, set *change.
bool fs_mgr_overlayfs_teardown(const char* mount_point, bool* change) {
    if (change) *change = false;
    mount_point = fs_mgr_mount_point(std::unique_ptr<fstab, decltype(&fs_mgr_free_fstab)>(
                                             fs_mgr_read_fstab_default(), fs_mgr_free_fstab)
                                             .get(),
                                     mount_point);
    auto ret = true;
    const auto overlay = kOverlayMountPoint + kOverlayTopDir;
    const auto oldpath = overlay + (mount_point ? "/"s + mount_point : ""s);
    const auto newpath = oldpath + ".teardown";
    ret &= fs_mgr_rm_all(newpath);
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
    if (mount_point) {
        save_errno = errno;
        if (!rmdir(overlay.c_str())) {
            if (change) *change = true;
        } else if ((errno != ENOENT) && (errno != ENOTEMPTY)) {
            ret = false;
            PERROR << "rmdir " << overlay;
        } else {
            errno = save_errno;
        }
    }
    if (!fs_mgr_wants_overlayfs()) {
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
    return ret;
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
