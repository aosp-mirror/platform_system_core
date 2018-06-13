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
#include <linux/fs.h>
#include <selinux/selinux.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>

#include "fs_mgr_priv.h"

using namespace std::literals;

#if ALLOW_ADBD_DISABLE_VERITY == 0  // If we are a user build, provide stubs

bool fs_mgr_overlayfs_mount_all() {
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

    static constexpr int percent = 1;  // 1%

    return (vst.f_bfree >= (vst.f_blocks * percent / 100));
}

bool fs_mgr_overlayfs_enabled(const struct fstab_rec* fsrec) {
    // readonly filesystem, can not be mount -o remount,rw
    // if squashfs or if free space is (near) zero making
    // such a remount virtually useless.
    return ("squashfs"s == fsrec->fs_type) || !fs_mgr_filesystem_has_space(fsrec->mount_point);
}

constexpr char upper_name[] = "upper";
constexpr char work_name[] = "work";

std::string fs_mgr_get_overlayfs_candidate(const std::string& mount_point) {
    if (!fs_mgr_is_dir(mount_point)) return "";
    auto dir = kOverlayMountPoint + "/overlay/" + android::base::Basename(mount_point) + "/";
    auto upper = dir + upper_name;
    if (!fs_mgr_is_dir(upper)) return "";
    auto work = dir + work_name;
    if (!fs_mgr_is_dir(work)) return "";
    if (!fs_mgr_dir_is_writable(work)) return "";
    return dir;
}

constexpr char lowerdir_option[] = "lowerdir=";
constexpr char upperdir_option[] = "upperdir=";

// default options for mount_point, returns empty string for none available.
std::string fs_mgr_get_overlayfs_options(const char* mount_point) {
    auto fsrec_mount_point = std::string(mount_point);
    auto candidate = fs_mgr_get_overlayfs_candidate(fsrec_mount_point);
    if (candidate.empty()) return "";

    auto context = fs_mgr_get_context(fsrec_mount_point);
    if (!context.empty()) context = ",rootcontext="s + context;
    return "override_creds=off,"s + lowerdir_option + fsrec_mount_point + "," + upperdir_option +
           candidate + upper_name + ",workdir=" + candidate + work_name + context;
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

std::string fs_mgr_get_overlayfs_options(const fstab* fstab, const char* mount_point) {
    if (fs_mgr_system_root_image(fstab) && ("/"s == mount_point)) mount_point = "/system";

    return fs_mgr_get_overlayfs_options(mount_point);
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

bool fs_mgr_wants_overlayfs(const fstab_rec* fsrec) {
    if (!fsrec) return false;

    auto fsrec_mount_point = fsrec->mount_point;
    if (!fsrec_mount_point) return false;

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

    // Verity enabled?
    const auto basename_mount_point(android::base::Basename(fsrec_mount_point));
    auto found = false;
    fs_mgr_update_verity_state(
            [&basename_mount_point, &found](fstab_rec*, const char* mount_point, int, int) {
                if (mount_point && (basename_mount_point == mount_point)) found = true;
            });
    return !found;
}

bool fs_mgr_rm_all(const std::string& path, bool* change = nullptr) {
    auto save_errno = errno;
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()), closedir);
    if (!dir) {
        if (errno == ENOENT) {
            errno = save_errno;
            return true;
        }
        PERROR << "overlayfs open " << path;
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
                PERROR << "overlayfs rmdir " << file;
            }
            continue;
        }
        if (!unlink(file.c_str())) {
            if (change) *change = true;
        } else {
            ret = false;
            PERROR << "overlayfs rm " << file;
        }
    }
    return ret;
}

bool fs_mgr_overlayfs_setup_one(const std::string& overlay, const std::string& mount_point,
                                bool* change) {
    auto ret = true;
    auto fsrec_mount_point = overlay + android::base::Basename(mount_point) + "/";
    auto save_errno = errno;
    if (!mkdir(fsrec_mount_point.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "overlayfs mkdir " << fsrec_mount_point;
    } else {
        errno = save_errno;
    }

    save_errno = errno;
    if (!mkdir((fsrec_mount_point + work_name).c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "overlayfs mkdir " << fsrec_mount_point << work_name;
    } else {
        errno = save_errno;
    }

    auto new_context = fs_mgr_get_context(mount_point);
    if (!new_context.empty() && setfscreatecon(new_context.c_str())) {
        ret = false;
        PERROR << "overlayfs setfscreatecon " << new_context;
    }
    auto upper = fsrec_mount_point + upper_name;
    save_errno = errno;
    if (!mkdir(upper.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        ret = false;
        PERROR << "overlayfs mkdir " << upper;
    } else {
        errno = save_errno;
    }
    if (!new_context.empty()) setfscreatecon(nullptr);

    return ret;
}

bool fs_mgr_overlayfs_mount(const fstab* fstab, const fstab_rec* fsrec) {
    if (!fs_mgr_wants_overlayfs(fsrec)) return false;
    auto fsrec_mount_point = fsrec->mount_point;
    if (!fsrec_mount_point || !fsrec_mount_point[0]) return false;
    auto options = fs_mgr_get_overlayfs_options(fstab, fsrec_mount_point);
    if (options.empty()) return false;

    // hijack __mount() report format to help triage
    auto report = "__mount(source=overlay,target="s + fsrec_mount_point + ",type=overlay";
    const auto opt_list = android::base::Split(options, ",");
    for (const auto opt : opt_list) {
        if (android::base::StartsWith(opt, upperdir_option)) {
            report = report + "," + opt;
            break;
        }
    }
    report = report + ")=";

    auto ret = mount("overlay", fsrec_mount_point, "overlay", MS_RDONLY | MS_RELATIME,
                     options.c_str());
    if (ret) {
        PERROR << report << ret;
        return false;
    } else {
        LINFO << report << ret;
        return true;
    }
}

bool fs_mgr_overlayfs_already_mounted(const char* mount_point) {
    if (!mount_point) return false;
    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(
            fs_mgr_read_fstab("/proc/mounts"), fs_mgr_free_fstab);
    if (!fstab) return false;
    const auto lowerdir = std::string(lowerdir_option) + mount_point;
    for (auto i = 0; i < fstab->num_entries; ++i) {
        const auto fsrec = &fstab->recs[i];
        const auto fs_type = fsrec->fs_type;
        if (!fs_type) continue;
        if (("overlay"s != fs_type) && ("overlayfs"s != fs_type)) continue;
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if (strcmp(fsrec_mount_point, mount_point)) continue;
        const auto fs_options = fsrec->fs_options;
        if (!fs_options) continue;
        const auto options = android::base::Split(fs_options, ",");
        for (const auto opt : options) {
            if (opt == lowerdir) {
                return true;
            }
        }
    }
    return false;
}

}  // namespace

bool fs_mgr_overlayfs_mount_all() {
    auto ret = false;

    if (!fs_mgr_wants_overlayfs()) return ret;

    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                                      fs_mgr_free_fstab);
    if (!fstab) return ret;

    for (auto i = 0; i < fstab->num_entries; i++) {
        const auto fsrec = &fstab->recs[i];
        auto fsrec_mount_point = fsrec->mount_point;
        if (!fsrec_mount_point) continue;
        if (fs_mgr_overlayfs_already_mounted(fsrec_mount_point)) continue;

        if (fs_mgr_overlayfs_mount(fstab.get(), fsrec)) ret = true;
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
        PERROR << "overlayfs setup";
        return ret;
    }

    std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(fs_mgr_read_fstab_default(),
                                                                      fs_mgr_free_fstab);
    std::vector<std::string> mounts;
    if (fstab) {
        if (!fs_mgr_get_entry_for_mount_point(fstab.get(), kOverlayMountPoint)) return ret;
        for (auto i = 0; i < fstab->num_entries; i++) {
            const auto fsrec = &fstab->recs[i];
            auto fsrec_mount_point = fsrec->mount_point;
            if (!fsrec_mount_point) continue;
            if (mount_point && strcmp(fsrec_mount_point, mount_point)) continue;
            if (!fs_mgr_wants_overlayfs(fsrec)) continue;
            mounts.emplace_back(fsrec_mount_point);
        }
        if (mounts.empty()) return ret;
    }

    if (mount_point && ("/"s == mount_point) && fs_mgr_system_root_image(fstab.get())) {
        mount_point = "/system";
    }
    auto overlay = kOverlayMountPoint + "/overlay/";
    auto save_errno = errno;
    if (!mkdir(overlay.c_str(), 0755)) {
        if (change) *change = true;
    } else if (errno != EEXIST) {
        PERROR << "overlayfs mkdir " << overlay;
    } else {
        errno = save_errno;
    }
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
    if (mount_point && ("/"s == mount_point)) {
        std::unique_ptr<struct fstab, decltype(&fs_mgr_free_fstab)> fstab(
                fs_mgr_read_fstab_default(), fs_mgr_free_fstab);
        if (fs_mgr_system_root_image(fstab.get())) mount_point = "/system";
    }
    auto ret = true;
    const auto overlay = kOverlayMountPoint + "/overlay";
    const auto oldpath = overlay + (mount_point ?: "");
    const auto newpath = oldpath + ".teardown";
    ret &= fs_mgr_rm_all(newpath);
    auto save_errno = errno;
    if (!rename(oldpath.c_str(), newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "overlayfs mv " << oldpath << " " << newpath;
    } else {
        errno = save_errno;
    }
    ret &= fs_mgr_rm_all(newpath, change);
    save_errno = errno;
    if (!rmdir(newpath.c_str())) {
        if (change) *change = true;
    } else if (errno != ENOENT) {
        ret = false;
        PERROR << "overlayfs rmdir " << newpath;
    } else {
        errno = save_errno;
    }
    if (mount_point) {
        save_errno = errno;
        if (!rmdir(overlay.c_str())) {
            if (change) *change = true;
        } else if ((errno != ENOENT) && (errno != ENOTEMPTY)) {
            ret = false;
            PERROR << "overlayfs rmdir " << overlay;
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
        PERROR << "overlayfs teardown";
        ret = false;
    }
    return ret;
}

#endif  // ALLOW_ADBD_DISABLE_VERITY != 0
