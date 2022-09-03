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

#include <getopt.h>
#include <stdio.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <binder/ProcessState.h>
#include <cutils/android_reboot.h>
#include <fs_mgr_overlayfs.h>
#include <libavb_user/libavb_user.h>

using namespace std::string_literals;

namespace {

void print_usage() {
  printf(
      "Usage:\n"
      "\tdisable-verity\n"
      "\tenable-verity\n"
      "\tset-verity-state [0|1]\n"
      "Options:\n"
      "\t-h --help\tthis help\n"
      "\t-R --reboot\tautomatic reboot if needed for new settings to take effect\n"
      "\t-v --verbose\tbe noisy\n");
}

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

[[noreturn]] void reboot(const std::string& name) {
  LOG(INFO) << "Rebooting device for new settings to take effect";
  ::sync();
  android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot," + name);
  ::sleep(60);
  LOG(ERROR) << "Failed to reboot";
  ::exit(1);
}

bool overlayfs_setup(bool enable) {
  auto want_reboot = false;
  errno = 0;
  if (enable ? fs_mgr_overlayfs_setup(nullptr, &want_reboot)
             : fs_mgr_overlayfs_teardown(nullptr, &want_reboot)) {
    if (want_reboot) {
      LOG(INFO) << (enable ? "Enabled" : "Disabled") << " overlayfs";
    }
  } else {
    LOG(ERROR) << "Failed to " << (enable ? "enable" : "disable") << " overlayfs";
  }
  return want_reboot;
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

class MyLogger {
 public:
  explicit MyLogger(bool verbose) : verbose_(verbose) {}

  void operator()(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
                  const char* file, unsigned int line, const char* message) {
    // Hide log starting with '[fs_mgr]' unless it's an error.
    if (verbose_ || severity >= android::base::ERROR || message[0] != '[') {
      fprintf(stderr, "%s\n", message);
    }
    logd_(id, severity, tag, file, line, message);
  }

 private:
  android::base::LogdLogger logd_;
  bool verbose_;
};

}  // namespace

int main(int argc, char* argv[]) {
  bool auto_reboot = false;
  bool verbose = false;

  struct option longopts[] = {
      {"help", no_argument, nullptr, 'h'},
      {"reboot", no_argument, nullptr, 'R'},
      {"verbose", no_argument, nullptr, 'v'},
      {0, 0, nullptr, 0},
  };
  for (int opt; (opt = ::getopt_long(argc, argv, "hRv", longopts, nullptr)) != -1;) {
    switch (opt) {
      case 'h':
        print_usage();
        return 0;
      case 'R':
        auto_reboot = true;
        break;
      case 'v':
        verbose = true;
        break;
      default:
        print_usage();
        return 1;
    }
  }

  android::base::InitLogging(argv, MyLogger(verbose));

  bool enable_verity = false;
  const std::string progname = getprogname();
  if (progname == "enable-verity") {
    enable_verity = true;
  } else if (progname == "disable-verity") {
    enable_verity = false;
  } else if (optind < argc && (argv[optind] == "1"s || argv[optind] == "0"s)) {
    // progname "set-verity-state"
    enable_verity = (argv[optind] == "1"s);
  } else {
    print_usage();
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
    if (auto_reboot) {
      reboot(progname);
    }
    printf("Reboot the device for new settings to take effect\n");
  }

  return exit_code;
}
