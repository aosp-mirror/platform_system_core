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

#include <stdio.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <binder/ProcessState.h>
#include <fs_mgr_overlayfs.h>
#include <libavb_user/libavb_user.h>

using namespace std::string_literals;

namespace {

#ifdef ALLOW_DISABLE_VERITY
const bool kAllowDisableVerity = true;
#else
const bool kAllowDisableVerity = false;
#endif

/* Helper function to get A/B suffix, if any. If the device isn't
 * using A/B the empty string is returned. Otherwise either "_a",
 * "_b", ... is returned.
 */
std::string get_ab_suffix() {
  return android::base::GetProperty("ro.boot.slot_suffix", "");
}

bool is_avb_device_locked() {
  return android::base::GetProperty("ro.boot.vbmeta.device_state", "") == "locked";
}

bool is_debuggable() {
  return android::base::GetBoolProperty("ro.debuggable", false);
}

bool is_using_avb() {
  // Figure out if we're using VB1.0 or VB2.0 (aka AVB) - by
  // contract, androidboot.vbmeta.digest is set by the bootloader
  // when using AVB).
  return !android::base::GetProperty("ro.boot.vbmeta.digest", "").empty();
}

bool overlayfs_setup(bool enable) {
  auto change = false;
  errno = 0;
  if (enable ? fs_mgr_overlayfs_setup(nullptr, &change)
             : fs_mgr_overlayfs_teardown(nullptr, &change)) {
    if (change) {
      LOG(INFO) << (enable ? "Enabled" : "Disabled") << " overlayfs";
    }
  } else {
    LOG(ERROR) << "Failed to " << (enable ? "enable" : "disable") << " overlayfs";
  }
  return change;
}

struct SetVerityStateResult {
  bool success = false;
  bool want_reboot = false;
};

/* Use AVB to turn verity on/off */
SetVerityStateResult SetVerityState(bool enable_verity) {
  std::string ab_suffix = get_ab_suffix();
  bool verity_enabled = false;

  if (is_avb_device_locked()) {
    LOG(ERROR) << "Device must be bootloader unlocked to change verity state";
    return {};
  }

  std::unique_ptr<AvbOps, decltype(&avb_ops_user_free)> ops(avb_ops_user_new(), &avb_ops_user_free);
  if (!ops) {
    LOG(ERROR) << "Error getting AVB ops";
    return {};
  }

  if (!avb_user_verity_get(ops.get(), ab_suffix.c_str(), &verity_enabled)) {
    LOG(ERROR) << "Error getting verity state";
    return {};
  }

  if ((verity_enabled && enable_verity) || (!verity_enabled && !enable_verity)) {
    LOG(INFO) << "Verity is already " << (verity_enabled ? "enabled" : "disabled");
    return {.success = true, .want_reboot = false};
  }

  if (!avb_user_verity_set(ops.get(), ab_suffix.c_str(), enable_verity)) {
    LOG(ERROR) << "Error setting verity state";
    return {};
  }

  LOG(INFO) << "Successfully " << (enable_verity ? "enabled" : "disabled") << " verity";
  return {.success = true, .want_reboot = true};
}

void MyLogger(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
              const char* file, unsigned int line, const char* message) {
  // Hide log starting with '[fs_mgr]' unless it's an error.
  if (severity == android::base::ERROR || message[0] != '[') {
    fprintf(stderr, "%s\n", message);
  }
  static auto logd = android::base::LogdLogger();
  logd(id, severity, tag, file, line, message);
}

}  // namespace

int main(int argc, char* argv[]) {
  android::base::InitLogging(argv, MyLogger);

  if (argc == 0) {
    LOG(FATAL) << "set-verity-state called with empty argv";
  }

  bool enable_verity = false;
  std::string procname = android::base::Basename(argv[0]);
  if (procname == "enable-verity") {
    enable_verity = true;
  } else if (procname == "disable-verity") {
    enable_verity = false;
  } else if (argc == 2 && (argv[1] == "1"s || argv[1] == "0"s)) {
    enable_verity = (argv[1] == "1"s);
  } else {
    printf("usage: %s [1|0]\n", argv[0]);
    return 1;
  }

  if (!kAllowDisableVerity || !is_debuggable()) {
    errno = EPERM;
    PLOG(ERROR) << "Cannot disable/enable verity on user build";
    return 1;
  }

  if (getuid() != 0) {
    errno = EACCES;
    PLOG(ERROR) << "Must be running as root (adb root)";
    return 1;
  }

  if (!is_using_avb()) {
    LOG(ERROR) << "Expected AVB device, VB1.0 is no longer supported";
    return 1;
  }

  int exit_code = 0;
  bool want_reboot = false;

  auto ret = SetVerityState(enable_verity);
  if (ret.success) {
    want_reboot |= ret.want_reboot;
  } else {
    exit_code = 1;
  }

  // Disable any overlayfs unconditionally if we want verity enabled.
  // Enable overlayfs only if verity is successfully disabled or is already disabled.
  if (enable_verity || ret.success) {
    // Start a threadpool to service waitForService() callbacks as
    // fs_mgr_overlayfs_* might call waitForService() to get the image service.
    android::ProcessState::self()->startThreadPool();
    want_reboot |= overlayfs_setup(!enable_verity);
  }

  if (want_reboot) {
    printf("Reboot the device for new settings to take effect\n");
  }

  return exit_code;
}
