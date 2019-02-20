/*
 * Copyright (C) 2019 The Android Open Source Project
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
#include <getopt.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr_priv.h>
#include <fstab/fstab.h>

namespace {

[[noreturn]] void usage(int exit_status) {
    LOG(INFO) << getprogname()
              << " [-h]\n"
                 "\t-h --help\tthis help\n"
                 "\n"
                 "Remount all partitions read-write.\n"
                 "Verity must be disabled.";

    ::exit(exit_status);
}

bool remountable_partition(const android::fs_mgr::FstabEntry& entry) {
    if (entry.fs_mgr_flags.vold_managed) return false;
    if (entry.fs_mgr_flags.recovery_only) return false;
    if (entry.fs_mgr_flags.slot_select_other) return false;
    if (!(entry.flags & MS_RDONLY)) return false;
    if (entry.fs_type == "vfat") return false;
    return true;
}

const std::string system_mount_point(const android::fs_mgr::FstabEntry& entry) {
    if (entry.mount_point == "/") return "/system";
    return entry.mount_point;
}

const android::fs_mgr::FstabEntry* is_wrapped(const android::fs_mgr::Fstab& overlayfs_candidates,
                                              const android::fs_mgr::FstabEntry& entry) {
    auto mount_point = system_mount_point(entry);
    auto it = std::find_if(overlayfs_candidates.begin(), overlayfs_candidates.end(),
                           [&mount_point](const auto& entry) {
                               return android::base::StartsWith(mount_point,
                                                                system_mount_point(entry) + "/");
                           });
    if (it == overlayfs_candidates.end()) return nullptr;
    return &(*it);
}

void try_unmount_bionic(android::fs_mgr::Fstab* mounts) {
    static constexpr const char* kBionic = "/bionic";

    auto entry = GetEntryForMountPoint(mounts, kBionic);
    if (!entry) return;

    struct statfs buf;
    if (::statfs(kBionic, &buf) == -1) {
        PLOG(ERROR) << "statfs of " << kBionic;
        return;
    }
    if (buf.f_flags & MS_RDONLY) {
        // /bionic is on a read-only partition; can happen for
        // non-system-as-root-devices. Don' try to unmount.
        return;
    }
    fs_mgr_set_blk_ro(entry->blk_device, false);
    if (::mount(entry->blk_device.c_str(), entry->mount_point.c_str(), entry->fs_type.c_str(),
                MS_REMOUNT, nullptr) == -1) {
        PLOG(ERROR) << "remount of " << kBionic;
    }
}

void MyLogger(android::base::LogId, android::base::LogSeverity severity, const char*, const char*,
              unsigned int, const char* message) {
    static const char log_characters[] = "VD\0WEFF";
    if (severity < sizeof(log_characters)) {
        auto severity_char = log_characters[severity];
        if (severity_char) fprintf(stderr, "%c ", severity_char);
    }
    fprintf(stderr, "%s\n", message);
}

}  // namespace

int main(int argc, char* argv[]) {
    android::base::InitLogging(argv, MyLogger);

    enum {
        SUCCESS,
        NOT_USERDEBUG,
        BADARG,
        NOT_ROOT,
        NO_FSTAB,
        VERITY_PARTITION,
        BAD_OVERLAY,
        NO_MOUNTS,
        REMOUNT_FAILED,
    } retval = SUCCESS;

    // If somehow this executable is delivered on a "user" build, it can
    // not function, so providing a clear message to the caller rather than
    // letting if fall through and provide a lot of confusing failure messages.
    if (!ALLOW_ADBD_DISABLE_VERITY || (android::base::GetProperty("ro.debuggable", "0") != "1")) {
        LOG(ERROR) << "only functions on userdebug or eng builds";
        return NOT_USERDEBUG;
    }

    struct option longopts[] = {
            {"help", no_argument, nullptr, 'h'},
            {0, 0, nullptr, 0},
    };
    for (int opt; (opt = ::getopt_long(argc, argv, "h", longopts, nullptr)) != -1;) {
        switch (opt) {
            default:
                LOG(ERROR) << "Bad Argument -" << char(opt);
                usage(BADARG);
                break;
            case 'h':
                usage(SUCCESS);
                break;
        }
    }

    if (argc > optind) {
        LOG(ERROR) << "Bad Argument " << argv[optind];
        usage(BADARG);
    }

    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "must be run as root";
        return NOT_ROOT;
    }

    android::fs_mgr::Fstab fstab;
    auto fstab_read = android::fs_mgr::ReadDefaultFstab(&fstab);
    if (!fstab_read || fstab.empty()) {
        PLOG(ERROR) << "Failed to read default fstab";
        return NO_FSTAB;
    }

    // Generate the list of supported overlayfs mount points.
    auto overlayfs_candidates = fs_mgr_overlayfs_candidate_list(fstab);

    // Generate the all remountable partitions sub-list
    android::fs_mgr::Fstab partitions;
    for (auto const& entry : fstab) {
        if (!remountable_partition(entry)) continue;
        if (overlayfs_candidates.empty() ||
            GetEntryForMountPoint(&overlayfs_candidates, entry.mount_point) ||
            (is_wrapped(overlayfs_candidates, entry) == nullptr)) {
            partitions.emplace_back(entry);
        }
    }

    // Check verity and optionally setup overlayfs backing.
    for (auto it = partitions.begin(); it != partitions.end();) {
        auto& entry = *it;
        auto& mount_point = entry.mount_point;
        if (fs_mgr_is_verity_enabled(entry)) {
            LOG(ERROR) << "Verity enabled on " << mount_point << ", skipping";
            retval = VERITY_PARTITION;
            it = partitions.erase(it);
            continue;
        }

        auto change = false;
        errno = 0;
        if (fs_mgr_overlayfs_setup(nullptr, mount_point.c_str(), &change)) {
            if (change) {
                LOG(INFO) << "Using overlayfs for " << mount_point;
            }
        } else if (errno) {
            PLOG(ERROR) << "Overlayfs setup for " << mount_point << " failed, skipping";
            retval = BAD_OVERLAY;
            it = partitions.erase(it);
            continue;
        }
        ++it;
    }

    if (partitions.empty()) {
        LOG(WARNING) << "No partitions to remount";
        return retval;
    }

    // Mount overlayfs.
    if (!fs_mgr_overlayfs_mount_all(&partitions)) {
        retval = BAD_OVERLAY;
        PLOG(ERROR) << "Can not mount overlayfs for partitions";
    }

    // Get actual mounts _after_ overlayfs has been added.
    android::fs_mgr::Fstab mounts;
    if (!android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts) || mounts.empty()) {
        PLOG(ERROR) << "Failed to read /proc/mounts";
        retval = NO_MOUNTS;
    }

    // Remount selected partitions.
    for (auto& entry : partitions) {
        // unlock the r/o key for the mount point device
        if (entry.fs_mgr_flags.logical) {
            fs_mgr_update_logical_partition(&entry);
        }
        auto blk_device = entry.blk_device;
        auto mount_point = entry.mount_point;

        for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) {
            auto& rentry = *it;
            if (mount_point == rentry.mount_point) {
                blk_device = rentry.blk_device;
                break;
            }
            if ((mount_point == "/") && (rentry.mount_point == "/system")) {
                if (blk_device != "/dev/root") blk_device = rentry.blk_device;
                mount_point = "/system";
                break;
            }
        }
        fs_mgr_set_blk_ro(blk_device, false);

        // Now remount!
        if (::mount(blk_device.c_str(), mount_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                    nullptr) == 0) {
            continue;
        }
        if ((errno == EINVAL) && (mount_point != entry.mount_point)) {
            mount_point = entry.mount_point;
            if (::mount(blk_device.c_str(), mount_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                        nullptr) == 0) {
                continue;
            }
        }
        // If errno = EROFS at this point, we are dealing with r/o
        // filesystem types like squashfs, erofs or ext4 dedupe. We will
        // consider such a device that does not have CONFIG_OVERLAY_FS
        // in the kernel as a misconfigured and take no action.
        //
        // ext4 dedupe _can_ be worked around by performing a reboot into
        // recovery and fsck'ing.  However the current decision is to not
        // reboot to reserve only one shell command to do so (reboot).  In
        // the future, if this is a problem, a -R flag could be introduced
        // to give permission to do so and as a convenience also implement
        // verity disable operations.  We will require this functionality
        // in order for adb remount to call this executable instead of its
        // current internal code that recognizes the -R flag and logistics.
        PLOG(ERROR) << "failed to remount partition dev:" << blk_device << " mnt:" << mount_point;
        retval = REMOUNT_FAILED;
    }

    try_unmount_bionic(&mounts);

    return retval;
}
