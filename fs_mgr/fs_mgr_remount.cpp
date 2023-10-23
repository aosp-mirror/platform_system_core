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

#include <iostream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android/os/IVold.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr_priv.h>
#include <fstab/fstab.h>
#include <libavb_user/libavb_user.h>
#include <libgsi/libgsid.h>

#include "fs_mgr_overlayfs_control.h"
#include "fs_mgr_overlayfs_mount.h"

using namespace std::literals;
using android::fs_mgr::Fstab;
using android::fs_mgr::FstabEntry;

namespace {

void usage() {
    const std::string progname = getprogname();
    if (progname == "disable-verity" || progname == "enable-verity" ||
        progname == "set-verity-state") {
        std::cout << "Usage: disable-verity\n"
                  << "       enable-verity\n"
                  << "       set-verity-state [0|1]\n"
                  << R"(
Options:
    -h --help       this help
    -R --reboot     automatic reboot if needed for new settings to take effect
    -v --verbose    be noisy)"
                  << std::endl;
    } else {
        std::cout << "Usage: " << progname << " [-h] [-R] [-T fstab_file] [partition]...\n"
                  << R"(
Options:
    -h --help       this help
    -R --reboot     disable verity & reboot to facilitate remount
    -v --verbose    be noisy
    -T --fstab      custom fstab file location
    partition       specific partition(s) (empty does all)

Remount specified partition(s) read-write, by name or mount point.
-R notwithstanding, verity must be disabled on partition(s).
-R within a DSU guest system reboots into the DSU instead of the host system,
this command would enable DSU (one-shot) if not already enabled.)"
                  << std::endl;
    }
}

const std::string system_mount_point(const android::fs_mgr::FstabEntry& entry) {
    if (entry.mount_point == "/") return "/system";
    return entry.mount_point;
}

class MyLogger {
  public:
    explicit MyLogger(bool verbose) : verbose_(verbose) {}

    void operator()(android::base::LogId id, android::base::LogSeverity severity, const char* tag,
                    const char* file, unsigned int line, const char* message) {
        // By default, print ERROR logs and logs of this program (does not start with '[')
        // Print [libfs_mgr] INFO logs only if -v is given.
        if (verbose_ || severity >= android::base::ERROR || message[0] != '[') {
            fprintf(stderr, "%s\n", message);
        }
        logd_(id, severity, tag, file, line, message);
    }

  private:
    android::base::LogdLogger logd_;
    bool verbose_;
};

[[noreturn]] void reboot(const std::string& name) {
    LOG(INFO) << "Rebooting device for new settings to take effect";
    ::sync();
    android::base::SetProperty(ANDROID_RB_PROPERTY, "reboot," + name);
    ::sleep(60);
    LOG(ERROR) << "Failed to reboot";
    ::exit(1);
}

static android::sp<android::os::IVold> GetVold() {
    auto sm = android::defaultServiceManager();
    while (true) {
        if (auto binder = sm->checkService(android::String16("vold"))) {
            if (auto vold = android::interface_cast<android::os::IVold>(binder)) {
                return vold;
            }
        }
        std::this_thread::sleep_for(2s);
    }
}

static bool ReadFstab(const char* fstab_file, android::fs_mgr::Fstab* fstab) {
    if (fstab_file) {
        return android::fs_mgr::ReadFstabFromFile(fstab_file, fstab);
    }
    if (!android::fs_mgr::ReadDefaultFstab(fstab)) {
        return false;
    }

    // Manufacture a / entry from /proc/mounts if missing.
    if (!GetEntryForMountPoint(fstab, "/system") && !GetEntryForMountPoint(fstab, "/")) {
        android::fs_mgr::Fstab mounts;
        if (android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts)) {
            if (auto entry = GetEntryForMountPoint(&mounts, "/")) {
                if (entry->fs_type != "rootfs") fstab->emplace_back(*entry);
            }
        }
    }
    return true;
}

bool VerifyCheckpointing() {
    if (!android::base::GetBoolProperty("ro.virtual_ab.enabled", false) &&
        !android::base::GetBoolProperty("ro.virtual_ab.retrofit", false)) {
        return true;
    }

    // Virtual A/B devices can use /data as backing storage; make sure we're
    // not checkpointing.
    auto vold = GetVold();
    bool checkpointing = false;
    if (!vold->isCheckpointing(&checkpointing).isOk()) {
        LOG(ERROR) << "Could not determine checkpointing status.";
        return false;
    }
    if (checkpointing) {
        LOG(ERROR) << "Cannot use remount when a checkpoint is in progress.";
        LOG(ERROR) << "To force end checkpointing, call 'vdc checkpoint commitChanges'";
        LOG(ERROR) << "Warning: this can lead to data corruption if rolled back.";
        return false;
    }
    return true;
}

static bool IsRemountable(Fstab& candidates, const FstabEntry& entry) {
    if (entry.fs_mgr_flags.vold_managed || entry.fs_mgr_flags.recovery_only ||
        entry.fs_mgr_flags.slot_select_other) {
        return false;
    }
    if (!(entry.flags & MS_RDONLY)) {
        return false;
    }
    if (entry.fs_type == "vfat") {
        return false;
    }
    if (auto candidate_entry = GetEntryForMountPoint(&candidates, entry.mount_point)) {
        return candidate_entry->fs_type == entry.fs_type;
    }
    return true;
}

static Fstab::const_iterator FindPartition(const Fstab& fstab, const std::string& partition) {
    Fstab mounts;
    if (!android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts)) {
        LOG(ERROR) << "Failed to read /proc/mounts";
        return fstab.end();
    }

    for (auto iter = fstab.begin(); iter != fstab.end(); iter++) {
        const auto mount_point = system_mount_point(*iter);
        if (partition == mount_point || partition == android::base::Basename(mount_point)) {
            // In case fstab has multiple entries, pick the one that matches the
            // actual mounted filesystem type.
            auto proc_mount_point = (iter->mount_point == "/system") ? "/" : iter->mount_point;
            auto mounted = GetEntryForMountPoint(&mounts, proc_mount_point);
            if (mounted && mounted->fs_type == iter->fs_type) {
                return iter;
            }
        }
    }
    return fstab.end();
}

static Fstab GetAllRemountablePartitions(Fstab& fstab) {
    auto candidates = fs_mgr_overlayfs_candidate_list(fstab);

    Fstab partitions;
    for (const auto& entry : fstab) {
        if (IsRemountable(candidates, entry)) {
            partitions.emplace_back(entry);
        }
    }
    return partitions;
}

bool GetRemountList(const Fstab& fstab, const std::vector<std::string>& argv, Fstab* partitions) {
    auto candidates = fs_mgr_overlayfs_candidate_list(fstab);

    for (const auto& arg : argv) {
        std::string partition = arg;
        if (partition == "/") {
            partition = "/system";
        }

        auto it = FindPartition(fstab, partition);
        if (it == fstab.end()) {
            LOG(ERROR) << "Unknown partition " << arg;
            return false;
        }

        const FstabEntry* entry = &*it;

        // If it's already remounted, include it so it gets gracefully skipped
        // later on.
        if (!fs_mgr_overlayfs_already_mounted(entry->mount_point) &&
            !IsRemountable(candidates, *entry)) {
            LOG(ERROR) << "Invalid partition " << arg;
            return false;
        }
        if (GetEntryForMountPoint(partitions, entry->mount_point) != nullptr) {
            continue;
        }
        partitions->emplace_back(*entry);
    }

    return true;
}

struct RemountCheckResult {
    bool reboot_later = false;
    bool setup_overlayfs = false;
    bool disabled_verity = false;
    bool verity_error = false;
    bool remounted_anything = false;
};

bool CheckOverlayfs(Fstab* partitions, RemountCheckResult* result) {
    bool ok = true;
    for (auto it = partitions->begin(); it != partitions->end();) {
        auto& entry = *it;
        const auto& mount_point = entry.mount_point;

        if (fs_mgr_wants_overlayfs(&entry)) {
            bool want_reboot = false;
            bool force = result->disabled_verity;
            if (!fs_mgr_overlayfs_setup(*partitions, mount_point.c_str(), &want_reboot, force)) {
                LOG(ERROR) << "Overlayfs setup for " << mount_point << " failed, skipping";
                ok = false;
                it = partitions->erase(it);
                continue;
            }
            if (want_reboot) {
                LOG(INFO) << "Using overlayfs for " << mount_point;
                result->reboot_later = true;
                result->setup_overlayfs = true;
            }
        }
        it++;
    }
    return ok;
}

bool EnableDsuIfNeeded() {
    auto gsid = android::gsi::GetGsiService();
    if (!gsid) {
        return true;
    }

    auto dsu_running = false;
    if (auto status = gsid->isGsiRunning(&dsu_running); !status.isOk()) {
        LOG(ERROR) << "Failed to get DSU running state: " << status;
        return false;
    }
    auto dsu_enabled = false;
    if (auto status = gsid->isGsiEnabled(&dsu_enabled); !status.isOk()) {
        LOG(ERROR) << "Failed to get DSU enabled state: " << status;
        return false;
    }
    if (dsu_running && !dsu_enabled) {
        std::string dsu_slot;
        if (auto status = gsid->getActiveDsuSlot(&dsu_slot); !status.isOk()) {
            LOG(ERROR) << "Failed to get active DSU slot: " << status;
            return false;
        }
        LOG(INFO) << "DSU is running but disabled, enable DSU so that we stay within the "
                     "DSU guest system after reboot";
        int error = 0;
        if (auto status = gsid->enableGsi(/* oneShot = */ true, dsu_slot, &error); !status.isOk()) {
            LOG(ERROR) << "Failed to enable DSU: " << status;
            return false;
        }
        if (error != android::gsi::IGsiService::INSTALL_OK) {
            LOG(ERROR) << "Failed to enable DSU, error code: " << error;
            return false;
        }
        LOG(INFO) << "Successfully enabled DSU (one-shot mode)";
    }
    return true;
}

bool RemountPartition(Fstab& fstab, Fstab& mounts, FstabEntry& entry) {
    // unlock the r/o key for the mount point device
    if (entry.fs_mgr_flags.logical) {
        fs_mgr_update_logical_partition(&entry);
    }
    auto blk_device = entry.blk_device;
    auto mount_point = entry.mount_point;

    auto found = false;
    for (auto it = mounts.rbegin(); it != mounts.rend(); ++it) {
        auto& rentry = *it;
        if (mount_point == rentry.mount_point) {
            blk_device = rentry.blk_device;
            found = true;
            break;
        }
        // Find overlayfs mount point?
        if ((mount_point == "/" && rentry.mount_point == "/system") ||
            (mount_point == "/system" && rentry.mount_point == "/")) {
            blk_device = rentry.blk_device;
            mount_point = "/system";
            found = true;
            break;
        }
    }
    if (!found) {
        PLOG(INFO) << "skip unmounted partition dev:" << blk_device << " mnt:" << mount_point;
        return true;
    }
    if (blk_device == "/dev/root") {
        auto from_fstab = GetEntryForMountPoint(&fstab, mount_point);
        if (from_fstab) blk_device = from_fstab->blk_device;
    }
    fs_mgr_set_blk_ro(blk_device, false);

    // Find system-as-root mount point?
    if ((mount_point == "/system") && !GetEntryForMountPoint(&mounts, mount_point) &&
        GetEntryForMountPoint(&mounts, "/")) {
        mount_point = "/";
    }

    // Now remount!
    for (const auto& mnt_point : {mount_point, entry.mount_point}) {
        if (::mount(blk_device.c_str(), mnt_point.c_str(), entry.fs_type.c_str(), MS_REMOUNT,
                    nullptr) == 0) {
            LOG(INFO) << "Remounted " << mnt_point << " as RW";
            return true;
        }
        if (errno != EINVAL || mount_point == entry.mount_point) {
            break;
        }
    }

    PLOG(ERROR) << "failed to remount partition dev:" << blk_device << " mnt:" << mount_point;
    return false;
}

struct SetVerityStateResult {
    bool success = false;
    bool want_reboot = false;
};

SetVerityStateResult SetVerityState(bool enable_verity) {
    const auto ab_suffix = android::base::GetProperty("ro.boot.slot_suffix", "");
    std::unique_ptr<AvbOps, decltype(&avb_ops_user_free)> ops(avb_ops_user_new(),
                                                              &avb_ops_user_free);
    if (!ops) {
        LOG(ERROR) << "Error getting AVB ops";
        return {};
    }
    if (!avb_user_verity_set(ops.get(), ab_suffix.c_str(), enable_verity)) {
        LOG(ERROR) << "Error setting verity state";
        return {};
    }
    bool verification_enabled = false;
    if (!avb_user_verification_get(ops.get(), ab_suffix.c_str(), &verification_enabled)) {
        LOG(ERROR) << "Error getting verification state";
        return {};
    }
    if (!verification_enabled) {
        LOG(WARNING) << "AVB verification is disabled, "
                     << (enable_verity ? "enabling" : "disabling")
                     << " verity state may have no effect";
        return {.success = true, .want_reboot = false};
    }
    const auto verity_mode = android::base::GetProperty("ro.boot.veritymode", "");
    const bool was_enabled = (verity_mode != "disabled");
    if ((was_enabled && enable_verity) || (!was_enabled && !enable_verity)) {
        LOG(INFO) << "Verity is already " << (enable_verity ? "enabled" : "disabled");
        return {.success = true, .want_reboot = false};
    }
    LOG(INFO) << "Successfully " << (enable_verity ? "enabled" : "disabled") << " verity";
    return {.success = true, .want_reboot = true};
}

bool SetupOrTeardownOverlayfs(bool enable) {
    bool want_reboot = false;
    if (enable) {
        Fstab fstab;
        if (!ReadDefaultFstab(&fstab)) {
            LOG(ERROR) << "Could not read fstab.";
            return want_reboot;
        }
        if (!fs_mgr_overlayfs_setup(fstab, nullptr, &want_reboot)) {
            LOG(ERROR) << "Overlayfs setup failed.";
            return want_reboot;
        }
        if (want_reboot) {
            printf("enabling overlayfs\n");
        }
    } else {
        auto rv = fs_mgr_overlayfs_teardown(nullptr, &want_reboot);
        if (rv == OverlayfsTeardownResult::Error) {
            LOG(ERROR) << "Overlayfs teardown failed.";
            return want_reboot;
        }
        if (rv == OverlayfsTeardownResult::Busy) {
            LOG(ERROR) << "Overlayfs is still active until reboot.";
            return true;
        }
        if (want_reboot) {
            printf("disabling overlayfs\n");
        }
    }
    return want_reboot;
}

bool do_remount(Fstab& fstab, const std::vector<std::string>& partition_args,
                RemountCheckResult* check_result) {
    Fstab partitions;
    if (partition_args.empty()) {
        partitions = GetAllRemountablePartitions(fstab);
    } else {
        if (!GetRemountList(fstab, partition_args, &partitions)) {
            return false;
        }
    }

    // Disable verity.
    auto verity_result = SetVerityState(false /* enable_verity */);

    // Treat error as fatal and suggest reboot only if verity is enabled.
    // TODO(b/260041315): We check the device mapper for any "<partition>-verity" device present
    // instead of checking ro.boot.veritymode because emulator has incorrect property value.
    bool must_disable_verity = false;
    for (const auto& partition : partitions) {
        if (fs_mgr_is_verity_enabled(partition)) {
            must_disable_verity = true;
            break;
        }
    }
    if (must_disable_verity) {
        if (!verity_result.success) {
            return false;
        }
        if (verity_result.want_reboot) {
            check_result->reboot_later = true;
            check_result->disabled_verity = true;
        }
    }

    // Optionally setup overlayfs backing.
    bool ok = CheckOverlayfs(&partitions, check_result);

    if (partitions.empty() || check_result->disabled_verity) {
        if (partitions.empty()) {
            LOG(WARNING) << "No remountable partitions were found.";
        }
        return ok;
    }

    // Mount overlayfs.
    if (!fs_mgr_overlayfs_mount_all(&partitions)) {
        LOG(WARNING) << "Cannot mount overlayfs for some partitions";
        // Continue regardless to handle raw remount case.
    }

    // Get actual mounts _after_ overlayfs has been added.
    android::fs_mgr::Fstab mounts;
    if (!android::fs_mgr::ReadFstabFromFile("/proc/mounts", &mounts) || mounts.empty()) {
        PLOG(ERROR) << "Failed to read /proc/mounts";
        return false;
    }

    // Remount selected partitions.
    for (auto& entry : partitions) {
        if (RemountPartition(fstab, mounts, entry)) {
            check_result->remounted_anything = true;
        } else {
            ok = false;
        }
    }
    return ok;
}

}  // namespace

int main(int argc, char* argv[]) {
    // Do not use MyLogger() when running as clean_scratch_files, as stdout/stderr of daemon process
    // are discarded.
    if (argc > 0 && android::base::Basename(argv[0]) == "clean_scratch_files"s) {
        android::fs_mgr::CleanupOldScratchFiles();
        return EXIT_SUCCESS;
    }

    android::base::InitLogging(argv, MyLogger(false /* verbose */));

    const char* fstab_file = nullptr;
    bool auto_reboot = false;
    bool verbose = false;
    std::vector<std::string> partition_args;

    struct option longopts[] = {
            {"fstab", required_argument, nullptr, 'T'},
            {"help", no_argument, nullptr, 'h'},
            {"reboot", no_argument, nullptr, 'R'},
            {"verbose", no_argument, nullptr, 'v'},
            {0, 0, nullptr, 0},
    };
    for (int opt; (opt = ::getopt_long(argc, argv, "hRT:v", longopts, nullptr)) != -1;) {
        switch (opt) {
            case 'h':
                usage();
                return EXIT_SUCCESS;
            case 'R':
                auto_reboot = true;
                break;
            case 'T':
                if (fstab_file) {
                    LOG(ERROR) << "Cannot supply two fstabs: -T " << fstab_file << " -T " << optarg;
                    usage();
                    return EXIT_FAILURE;
                }
                fstab_file = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            default:
                LOG(ERROR) << "Bad argument -" << char(opt);
                usage();
                return EXIT_FAILURE;
        }
    }

    if (verbose) {
        android::base::SetLogger(MyLogger(verbose));
    }

    bool remount = false;
    bool enable_verity = false;
    const std::string progname = getprogname();
    if (progname == "enable-verity") {
        enable_verity = true;
    } else if (progname == "disable-verity") {
        enable_verity = false;
    } else if (progname == "set-verity-state") {
        if (optind < argc && (argv[optind] == "1"s || argv[optind] == "0"s)) {
            enable_verity = (argv[optind] == "1"s);
        } else {
            usage();
            return EXIT_FAILURE;
        }
    } else {
        remount = true;
        for (; optind < argc; ++optind) {
            partition_args.emplace_back(argv[optind]);
        }
    }

    // Make sure we are root.
    if (::getuid() != 0) {
        LOG(ERROR) << "Not running as root. Try \"adb root\" first.";
        return EXIT_FAILURE;
    }

    // If somehow this executable is delivered on a "user" build, it can
    // not function, so providing a clear message to the caller rather than
    // letting if fall through and provide a lot of confusing failure messages.
    if (!ALLOW_ADBD_DISABLE_VERITY || !android::base::GetBoolProperty("ro.debuggable", false)) {
        LOG(ERROR) << "Device must be userdebug build";
        return EXIT_FAILURE;
    }

    if (android::base::GetProperty("ro.boot.verifiedbootstate", "") != "orange") {
        LOG(ERROR) << "Device must be bootloader unlocked";
        return EXIT_FAILURE;
    }

    // Start a threadpool to service waitForService() callbacks as
    // fs_mgr_overlayfs_* might call waitForService() to get the image service.
    android::ProcessState::self()->startThreadPool();

    if (!remount) {
        auto ret = SetVerityState(enable_verity);

        // Disable any overlayfs unconditionally if we want verity enabled.
        // Enable overlayfs only if verity is successfully disabled or is already disabled.
        if (enable_verity || ret.success) {
            ret.want_reboot |= SetupOrTeardownOverlayfs(!enable_verity);
        }

        if (ret.want_reboot) {
            if (auto_reboot) {
                reboot(progname);
            }
            std::cout << "Reboot the device for new settings to take effect" << std::endl;
        }
        return ret.success ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    // Make sure checkpointing is disabled if necessary.
    if (!VerifyCheckpointing()) {
        return EXIT_FAILURE;
    }

    // Read the selected fstab.
    Fstab fstab;
    if (!ReadFstab(fstab_file, &fstab) || fstab.empty()) {
        PLOG(ERROR) << "Failed to read fstab";
        return EXIT_FAILURE;
    }

    RemountCheckResult check_result;
    bool remount_success = do_remount(fstab, partition_args, &check_result);

    if (check_result.disabled_verity && check_result.setup_overlayfs) {
        LOG(INFO) << "Verity disabled; overlayfs enabled.";
    } else if (check_result.disabled_verity) {
        LOG(INFO) << "Verity disabled.";
    } else if (check_result.setup_overlayfs) {
        LOG(INFO) << "Overlayfs enabled.";
    }
    if (remount_success && check_result.remounted_anything) {
        LOG(INFO) << "Remount succeeded";
    } else if (!remount_success) {
        LOG(ERROR) << "Remount failed";
    }
    if (check_result.reboot_later) {
        if (auto_reboot) {
            // If (1) remount requires a reboot to take effect, (2) system is currently
            // running a DSU guest and (3) DSU is disabled, then enable DSU so that the
            // next reboot would not take us back to the host system but stay within
            // the guest system.
            if (!EnableDsuIfNeeded()) {
                LOG(ERROR) << "Unable to automatically enable DSU";
                return EXIT_FAILURE;
            }
            reboot("remount");
        } else {
            LOG(INFO) << "Now reboot your device for settings to take effect";
        }
        return EXIT_SUCCESS;
    }
    return remount_success ? EXIT_SUCCESS : EXIT_FAILURE;
}
