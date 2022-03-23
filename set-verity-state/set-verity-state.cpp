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
#include <fcntl.h>
#include <inttypes.h>
#include <libavb_user/libavb_user.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <fs_mgr.h>
#include <fs_mgr_overlayfs.h>
#include <fstab/fstab.h>
#include <log/log_properties.h>

#include "fec/io.h"

#ifdef ALLOW_DISABLE_VERITY
static const bool kAllowDisableVerity = true;
#else
static const bool kAllowDisableVerity = false;
#endif

using android::base::unique_fd;

static void suggest_run_adb_root() {
  if (getuid() != 0) printf("Maybe run adb root?\n");
}

static bool make_block_device_writable(const std::string& dev) {
  unique_fd fd(open(dev.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    return false;
  }

  int OFF = 0;
  bool result = (ioctl(fd.get(), BLKROSET, &OFF) != -1);
  return result;
}

/* Turn verity on/off */
static bool set_verity_enabled_state(const char* block_device, const char* mount_point,
                                     bool enable) {
  if (!make_block_device_writable(block_device)) {
    printf("Could not make block device %s writable (%s).\n", block_device, strerror(errno));
    return false;
  }

  fec::io fh(block_device, O_RDWR);

  if (!fh) {
    printf("Could not open block device %s (%s).\n", block_device, strerror(errno));
    suggest_run_adb_root();
    return false;
  }

  fec_verity_metadata metadata;

  if (!fh.get_verity_metadata(metadata)) {
    printf("Couldn't find verity metadata!\n");
    return false;
  }

  if (!enable && metadata.disabled) {
    printf("Verity already disabled on %s\n", mount_point);
    return false;
  }

  if (enable && !metadata.disabled) {
    printf("Verity already enabled on %s\n", mount_point);
    return false;
  }

  if (!fh.set_verity_status(enable)) {
    printf("Could not set verity %s flag on device %s with error %s\n",
           enable ? "enabled" : "disabled", block_device, strerror(errno));
    return false;
  }

  auto change = false;
  errno = 0;
  if (enable ? fs_mgr_overlayfs_teardown(mount_point, &change)
             : fs_mgr_overlayfs_setup(nullptr, mount_point, &change)) {
    if (change) {
      printf("%s overlayfs for %s\n", enable ? "disabling" : "using", mount_point);
    }
  } else if (errno) {
    int expected_errno = enable ? EBUSY : ENOENT;
    if (errno != expected_errno) {
      printf("Overlayfs %s for %s failed with error %s\n", enable ? "teardown" : "setup",
             mount_point, strerror(errno));
    }
  }
  printf("Verity %s on %s\n", enable ? "enabled" : "disabled", mount_point);
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

static bool overlayfs_setup(bool enable) {
  auto change = false;
  errno = 0;
  if (enable ? fs_mgr_overlayfs_teardown(nullptr, &change)
             : fs_mgr_overlayfs_setup(nullptr, nullptr, &change)) {
    if (change) {
      printf("%s overlayfs\n", enable ? "disabling" : "using");
    }
  } else if (errno) {
    printf("Overlayfs %s failed with error %s\n", enable ? "teardown" : "setup", strerror(errno));
    suggest_run_adb_root();
  }
  return change;
}

/* Use AVB to turn verity on/off */
static bool set_avb_verity_enabled_state(AvbOps* ops, bool enable_verity) {
  std::string ab_suffix = get_ab_suffix();
  bool verity_enabled;

  if (is_avb_device_locked()) {
    printf("Device is locked. Please unlock the device first\n");
    return false;
  }

  if (!avb_user_verity_get(ops, ab_suffix.c_str(), &verity_enabled)) {
    printf("Error getting verity state. Try adb root first?\n");
    return false;
  }

  if ((verity_enabled && enable_verity) || (!verity_enabled && !enable_verity)) {
    printf("verity is already %s\n", verity_enabled ? "enabled" : "disabled");
    return false;
  }

  if (!avb_user_verity_set(ops, ab_suffix.c_str(), enable_verity)) {
    printf("Error setting verity\n");
    return false;
  }

  overlayfs_setup(enable_verity);
  printf("Successfully %s verity\n", enable_verity ? "enabled" : "disabled");
  return true;
}

int main(int argc, char* argv[]) {
  if (argc == 0) {
    LOG(FATAL) << "set-verity-state called with empty argv";
  }

  std::optional<bool> enable_opt;
  std::string procname = android::base::Basename(argv[0]);
  if (procname == "enable-verity") {
    enable_opt = true;
  } else if (procname == "disable-verity") {
    enable_opt = false;
  }

  if (!enable_opt.has_value()) {
    if (argc != 2) {
      printf("usage: %s [1|0]\n", argv[0]);
      return 1;
    }

    if (strcmp(argv[1], "1") == 0) {
      enable_opt = true;
    } else if (strcmp(argv[1], "0") == 0) {
      enable_opt = false;
    } else {
      printf("usage: %s [1|0]\n", argv[0]);
      return 1;
    }
  }

  bool enable = enable_opt.value();

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
      printf("%s only works for userdebug builds\n", argv[0]);
    }

    if (!android::base::GetBoolProperty("ro.secure", false)) {
      overlayfs_setup(enable);
      printf("verity not enabled - ENG build\n");
      return 0;
    }
  }

  // Should never be possible to disable dm-verity on a USER build
  // regardless of using AVB or VB1.0.
  if (!__android_log_is_debuggable()) {
    printf("verity cannot be disabled/enabled - USER build\n");
    return 0;
  }

  if (using_avb) {
    // Yep, the system is using AVB.
    AvbOps* ops = avb_ops_user_new();
    if (ops == nullptr) {
      printf("Error getting AVB ops\n");
      return 1;
    }
    if (set_avb_verity_enabled_state(ops, enable)) {
      any_changed = true;
    }
    avb_ops_user_free(ops);
  } else {
    // Not using AVB - assume VB1.0.

    // read all fstab entries at once from all sources
    android::fs_mgr::Fstab fstab;
    if (!android::fs_mgr::ReadDefaultFstab(&fstab)) {
      printf("Failed to read fstab\n");
      suggest_run_adb_root();
      return 0;
    }

    // Loop through entries looking for ones that verity manages.
    for (const auto& entry : fstab) {
      if (entry.fs_mgr_flags.verify) {
        if (set_verity_enabled_state(entry.blk_device.c_str(), entry.mount_point.c_str(), enable)) {
          any_changed = true;
        }
      }
    }
  }
  if (!any_changed) any_changed = overlayfs_setup(enable);

  if (any_changed) {
    printf("Now reboot your device for settings to take effect\n");
  }

  return 0;
}
