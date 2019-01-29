/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "set_verity_enable_state_service.h"
#include "sysdeps.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libavb_user/libavb_user.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/stat.h>

#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <fs_mgr.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <log/log_properties.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "remount_service.h"

#include "fec/io.h"

#ifdef ALLOW_ADBD_DISABLE_VERITY
static const bool kAllowDisableVerity = true;
#else
static const bool kAllowDisableVerity = false;
#endif

void suggest_run_adb_root(int fd) {
    if (getuid() != 0) WriteFdExactly(fd, "Maybe run adb root?\n");
}

/* Turn verity on/off */
static bool set_verity_enabled_state(int fd, const char* block_device, const char* mount_point,
                                     bool enable) {
    if (!make_block_device_writable(block_device)) {
        WriteFdFmt(fd, "Could not make block device %s writable (%s).\n",
                   block_device, strerror(errno));
        return false;
    }

    fec::io fh(block_device, O_RDWR);

    if (!fh) {
        WriteFdFmt(fd, "Could not open block device %s (%s).\n", block_device, strerror(errno));
        suggest_run_adb_root(fd);
        return false;
    }

    fec_verity_metadata metadata;

    if (!fh.get_verity_metadata(metadata)) {
        WriteFdExactly(fd, "Couldn't find verity metadata!\n");
        return false;
    }

    if (!enable && metadata.disabled) {
        WriteFdFmt(fd, "Verity already disabled on %s\n", mount_point);
        return false;
    }

    if (enable && !metadata.disabled) {
        WriteFdFmt(fd, "Verity already enabled on %s\n", mount_point);
        return false;
    }

    if (!fh.set_verity_status(enable)) {
        WriteFdFmt(fd, "Could not set verity %s flag on device %s with error %s\n",
                   enable ? "enabled" : "disabled",
                   block_device, strerror(errno));
        return false;
    }

    auto change = false;
    errno = 0;
    if (enable ? fs_mgr_overlayfs_teardown(mount_point, &change)
               : fs_mgr_overlayfs_setup(nullptr, mount_point, &change)) {
        if (change) {
            WriteFdFmt(fd, "%s overlayfs for %s\n", enable ? "disabling" : "using", mount_point);
        }
    } else if (errno) {
        WriteFdFmt(fd, "Overlayfs %s for %s failed with error %s\n", enable ? "teardown" : "setup",
                   mount_point, strerror(errno));
    }
    WriteFdFmt(fd, "Verity %s on %s\n", enable ? "enabled" : "disabled", mount_point);
    return true;
}

/* Helper function to get A/B suffix, if any. If the device isn't
 * using A/B the empty string is returned. Otherwise either "_a",
 * "_b", ... is returned.
 */
static std::string get_ab_suffix() {
    return android::base::GetProperty("ro.boot.slot_suffix", "");
}

static bool is_avb_device_locked() {
    return android::base::GetProperty("ro.boot.vbmeta.device_state", "") == "locked";
}

static bool overlayfs_setup(int fd, bool enable) {
    auto change = false;
    errno = 0;
    if (enable ? fs_mgr_overlayfs_teardown(nullptr, &change)
               : fs_mgr_overlayfs_setup(nullptr, nullptr, &change)) {
        if (change) {
            WriteFdFmt(fd, "%s overlayfs\n", enable ? "disabling" : "using");
        }
    } else if (errno) {
        WriteFdFmt(fd, "Overlayfs %s failed with error %s\n", enable ? "teardown" : "setup",
                   strerror(errno));
        suggest_run_adb_root(fd);
    }
    return change;
}

/* Use AVB to turn verity on/off */
static bool set_avb_verity_enabled_state(int fd, AvbOps* ops, bool enable_verity) {
    std::string ab_suffix = get_ab_suffix();
    bool verity_enabled;

    if (is_avb_device_locked()) {
        WriteFdExactly(fd, "Device is locked. Please unlock the device first\n");
        return false;
    }

    if (!avb_user_verity_get(ops, ab_suffix.c_str(), &verity_enabled)) {
        WriteFdExactly(fd, "Error getting verity state. Try adb root first?\n");
        return false;
    }

    if ((verity_enabled && enable_verity) || (!verity_enabled && !enable_verity)) {
        WriteFdFmt(fd, "verity is already %s\n", verity_enabled ? "enabled" : "disabled");
        return false;
    }

    if (!avb_user_verity_set(ops, ab_suffix.c_str(), enable_verity)) {
        WriteFdExactly(fd, "Error setting verity\n");
        return false;
    }

    overlayfs_setup(fd, enable_verity);
    WriteFdFmt(fd, "Successfully %s verity\n", enable_verity ? "enabled" : "disabled");
    return true;
}

void set_verity_enabled_state_service(unique_fd fd, bool enable) {
    bool any_changed = false;

    // Figure out if we're using VB1.0 or VB2.0 (aka AVB) - by
    // contract, androidboot.vbmeta.digest is set by the bootloader
    // when using AVB).
    bool using_avb = !android::base::GetProperty("ro.boot.vbmeta.digest", "").empty();

    // If using AVB, dm-verity is used on any build so we want it to
    // be possible to disable/enable on any build (except USER). For
    // VB1.0 dm-verity is only enabled on certain builds.
    if (!using_avb) {
        if (!kAllowDisableVerity) {
            WriteFdFmt(fd.get(), "%s-verity only works for userdebug builds\n",
                       enable ? "enable" : "disable");
        }

        if (!android::base::GetBoolProperty("ro.secure", false)) {
            overlayfs_setup(fd, enable);
            WriteFdExactly(fd.get(), "verity not enabled - ENG build\n");
            return;
        }
    }

    // Should never be possible to disable dm-verity on a USER build
    // regardless of using AVB or VB1.0.
    if (!__android_log_is_debuggable()) {
        WriteFdExactly(fd.get(), "verity cannot be disabled/enabled - USER build\n");
        return;
    }

    if (using_avb) {
        // Yep, the system is using AVB.
        AvbOps* ops = avb_ops_user_new();
        if (ops == nullptr) {
            WriteFdExactly(fd.get(), "Error getting AVB ops\n");
            return;
        }
        if (set_avb_verity_enabled_state(fd.get(), ops, enable)) {
            any_changed = true;
        }
        avb_ops_user_free(ops);
    } else {
        // Not using AVB - assume VB1.0.

        // read all fstab entries at once from all sources
        Fstab fstab;
        if (!ReadDefaultFstab(&fstab)) {
            WriteFdExactly(fd.get(), "Failed to read fstab\n");
            suggest_run_adb_root(fd.get());
            return;
        }

        // Loop through entries looking for ones that verity manages.
        for (const auto& entry : fstab) {
            if (entry.fs_mgr_flags.verify) {
                if (set_verity_enabled_state(fd.get(), entry.blk_device.c_str(),
                                             entry.mount_point.c_str(), enable)) {
                    any_changed = true;
                }
            }
        }
    }
    if (!any_changed) any_changed = overlayfs_setup(fd, enable);

    if (any_changed) {
        WriteFdExactly(fd.get(), "Now reboot your device for settings to take effect\n");
    }
}
