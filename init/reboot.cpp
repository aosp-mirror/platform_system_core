/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "reboot.h"

#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <mntent.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <memory>
#include <set>
#include <thread>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fs_mgr.h>
#include <logwrap/logwrap.h>
#include <private/android_filesystem_config.h>
#include <selinux/selinux.h>

#include "action_manager.h"
#include "init.h"
#include "property_service.h"
#include "reboot_utils.h"
#include "service.h"
#include "sigchld_handler.h"

using android::base::Split;
using android::base::StringPrintf;
using android::base::Timer;

namespace android {
namespace init {

// represents umount status during reboot / shutdown.
enum UmountStat {
    /* umount succeeded. */
    UMOUNT_STAT_SUCCESS = 0,
    /* umount was not run. */
    UMOUNT_STAT_SKIPPED = 1,
    /* umount failed with timeout. */
    UMOUNT_STAT_TIMEOUT = 2,
    /* could not run due to error */
    UMOUNT_STAT_ERROR = 3,
    /* not used by init but reserved for other part to use this to represent the
       the state where umount status before reboot is not found / available. */
    UMOUNT_STAT_NOT_AVAILABLE = 4,
};

// Utility for struct mntent
class MountEntry {
  public:
    explicit MountEntry(const mntent& entry)
        : mnt_fsname_(entry.mnt_fsname),
          mnt_dir_(entry.mnt_dir),
          mnt_type_(entry.mnt_type),
          mnt_opts_(entry.mnt_opts) {}

    bool Umount(bool force) {
        LOG(INFO) << "Unmounting " << mnt_fsname_ << ":" << mnt_dir_ << " opts " << mnt_opts_;
        int r = umount2(mnt_dir_.c_str(), force ? MNT_FORCE : 0);
        if (r == 0) {
            LOG(INFO) << "Umounted " << mnt_fsname_ << ":" << mnt_dir_ << " opts " << mnt_opts_;
            return true;
        } else {
            PLOG(WARNING) << "Cannot umount " << mnt_fsname_ << ":" << mnt_dir_ << " opts "
                          << mnt_opts_;
            return false;
        }
    }

    void DoFsck() {
        int st;
        if (IsF2Fs()) {
            const char* f2fs_argv[] = {
                "/system/bin/fsck.f2fs", "-f", mnt_fsname_.c_str(),
            };
            android_fork_execvp_ext(arraysize(f2fs_argv), (char**)f2fs_argv, &st, true, LOG_KLOG,
                                    true, nullptr, nullptr, 0);
        } else if (IsExt4()) {
            const char* ext4_argv[] = {
                "/system/bin/e2fsck", "-f", "-y", mnt_fsname_.c_str(),
            };
            android_fork_execvp_ext(arraysize(ext4_argv), (char**)ext4_argv, &st, true, LOG_KLOG,
                                    true, nullptr, nullptr, 0);
        }
    }

    static bool IsBlockDevice(const struct mntent& mntent) {
        return android::base::StartsWith(mntent.mnt_fsname, "/dev/block");
    }

    static bool IsEmulatedDevice(const struct mntent& mntent) {
        return android::base::StartsWith(mntent.mnt_fsname, "/data/");
    }

  private:
    bool IsF2Fs() const { return mnt_type_ == "f2fs"; }

    bool IsExt4() const { return mnt_type_ == "ext4"; }

    std::string mnt_fsname_;
    std::string mnt_dir_;
    std::string mnt_type_;
    std::string mnt_opts_;
};

// Turn off backlight while we are performing power down cleanup activities.
static void TurnOffBacklight() {
    Service* service = ServiceList::GetInstance().FindService("blank_screen");
    if (service == nullptr) {
        LOG(WARNING) << "cannot find blank_screen in TurnOffBacklight";
        return;
    }
    service->Start();
}

static void ShutdownVold() {
    const char* vdc_argv[] = {"/system/bin/vdc", "volume", "shutdown"};
    int status;
    android_fork_execvp_ext(arraysize(vdc_argv), (char**)vdc_argv, &status, true, LOG_KLOG, true,
                            nullptr, nullptr, 0);
}

static void LogShutdownTime(UmountStat stat, Timer* t) {
    LOG(WARNING) << "powerctl_shutdown_time_ms:" << std::to_string(t->duration().count()) << ":"
                 << stat;
}

/* Find all read+write block devices and emulated devices in /proc/mounts
 * and add them to correpsponding list.
 */
static bool FindPartitionsToUmount(std::vector<MountEntry>* blockDevPartitions,
                                   std::vector<MountEntry>* emulatedPartitions, bool dump) {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return false;
    }
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        if (dump) {
            LOG(INFO) << "mount entry " << mentry->mnt_fsname << ":" << mentry->mnt_dir << " opts "
                      << mentry->mnt_opts << " type " << mentry->mnt_type;
        } else if (MountEntry::IsBlockDevice(*mentry) && hasmntopt(mentry, "rw")) {
            std::string mount_dir(mentry->mnt_dir);
            // These are R/O partitions changed to R/W after adb remount.
            // Do not umount them as shutdown critical services may rely on them.
            if (mount_dir != "/" && mount_dir != "/system" && mount_dir != "/vendor" &&
                mount_dir != "/oem") {
                blockDevPartitions->emplace(blockDevPartitions->begin(), *mentry);
            }
        } else if (MountEntry::IsEmulatedDevice(*mentry)) {
            emulatedPartitions->emplace(emulatedPartitions->begin(), *mentry);
        }
    }
    return true;
}

static void DumpUmountDebuggingInfo(bool dump_all) {
    int status;
    if (!security_getenforce()) {
        LOG(INFO) << "Run lsof";
        const char* lsof_argv[] = {"/system/bin/lsof"};
        android_fork_execvp_ext(arraysize(lsof_argv), (char**)lsof_argv, &status, true, LOG_KLOG,
                                true, nullptr, nullptr, 0);
    }
    FindPartitionsToUmount(nullptr, nullptr, true);
    if (dump_all) {
        // dump current tasks, this log can be lengthy, so only dump with dump_all
        android::base::WriteStringToFile("t", "/proc/sysrq-trigger");
    }
}

static UmountStat UmountPartitions(std::chrono::milliseconds timeout) {
    Timer t;
    /* data partition needs all pending writes to be completed and all emulated partitions
     * umounted.If the current waiting is not good enough, give
     * up and leave it to e2fsck after reboot to fix it.
     */
    while (true) {
        std::vector<MountEntry> block_devices;
        std::vector<MountEntry> emulated_devices;
        if (!FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
            return UMOUNT_STAT_ERROR;
        }
        if (block_devices.size() == 0) {
            return UMOUNT_STAT_SUCCESS;
        }
        bool unmount_done = true;
        if (emulated_devices.size() > 0) {
            for (auto& entry : emulated_devices) {
                if (!entry.Umount(false)) unmount_done = false;
            }
            if (unmount_done) {
                sync();
            }
        }
        for (auto& entry : block_devices) {
            if (!entry.Umount(timeout == 0ms)) unmount_done = false;
        }
        if (unmount_done) {
            return UMOUNT_STAT_SUCCESS;
        }
        if ((timeout < t.duration())) {  // try umount at least once
            return UMOUNT_STAT_TIMEOUT;
        }
        std::this_thread::sleep_for(100ms);
    }
}

static void KillAllProcesses() { android::base::WriteStringToFile("i", "/proc/sysrq-trigger"); }

/* Try umounting all emulated file systems R/W block device cfile systems.
 * This will just try umount and give it up if it fails.
 * For fs like ext4, this is ok as file system will be marked as unclean shutdown
 * and necessary check can be done at the next reboot.
 * For safer shutdown, caller needs to make sure that
 * all processes / emulated partition for the target fs are all cleaned-up.
 *
 * return true when umount was successful. false when timed out.
 */
static UmountStat TryUmountAndFsck(bool runFsck, std::chrono::milliseconds timeout) {
    Timer t;
    std::vector<MountEntry> block_devices;
    std::vector<MountEntry> emulated_devices;

    if (runFsck && !FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
        return UMOUNT_STAT_ERROR;
    }

    UmountStat stat = UmountPartitions(timeout - t.duration());
    if (stat != UMOUNT_STAT_SUCCESS) {
        LOG(INFO) << "umount timeout, last resort, kill all and try";
        if (DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo(true);
        KillAllProcesses();
        // even if it succeeds, still it is timeout and do not run fsck with all processes killed
        UmountStat st = UmountPartitions(0ms);
        if ((st != UMOUNT_STAT_SUCCESS) && DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo(false);
    }

    if (stat == UMOUNT_STAT_SUCCESS && runFsck) {
        // fsck part is excluded from timeout check. It only runs for user initiated shutdown
        // and should not affect reboot time.
        for (auto& entry : block_devices) {
            entry.DoFsck();
        }
    }
    return stat;
}

//* Reboot / shutdown the system.
// cmd ANDROID_RB_* as defined in android_reboot.h
// reason Reason string like "reboot", "shutdown,userrequested"
// rebootTarget Reboot target string like "bootloader". Otherwise, it should be an
//              empty string.
// runFsck Whether to run fsck after umount is done.
//
static void DoReboot(unsigned int cmd, const std::string& reason, const std::string& rebootTarget,
                     bool runFsck) {
    Timer t;
    LOG(INFO) << "Reboot start, reason: " << reason << ", rebootTarget: " << rebootTarget;

    // Ensure last reboot reason is reduced to canonical
    // alias reported in bootloader or system boot reason.
    size_t skip = 0;
    std::vector<std::string> reasons = Split(reason, ",");
    if (reasons.size() >= 2 && reasons[0] == "reboot" &&
        (reasons[1] == "recovery" || reasons[1] == "bootloader" || reasons[1] == "cold" ||
         reasons[1] == "hard" || reasons[1] == "warm")) {
        skip = strlen("reboot,");
    }
    property_set(LAST_REBOOT_REASON_PROPERTY, reason.c_str() + skip);
    sync();

    bool is_thermal_shutdown = cmd == ANDROID_RB_THERMOFF;

    auto shutdown_timeout = 0ms;
    if (!SHUTDOWN_ZERO_TIMEOUT) {
        if (is_thermal_shutdown) {
            constexpr unsigned int thermal_shutdown_timeout = 1;
            shutdown_timeout = std::chrono::seconds(thermal_shutdown_timeout);
        } else {
            constexpr unsigned int shutdown_timeout_default = 6;
            auto shutdown_timeout_property = android::base::GetUintProperty(
                "ro.build.shutdown_timeout", shutdown_timeout_default);
            shutdown_timeout = std::chrono::seconds(shutdown_timeout_property);
        }
    }
    LOG(INFO) << "Shutdown timeout: " << shutdown_timeout.count() << " ms";

    // keep debugging tools until non critical ones are all gone.
    const std::set<std::string> kill_after_apps{"tombstoned", "logd", "adbd"};
    // watchdogd is a vendor specific component but should be alive to complete shutdown safely.
    const std::set<std::string> to_starts{"watchdogd"};
    for (const auto& s : ServiceList::GetInstance()) {
        if (kill_after_apps.count(s->name())) {
            s->SetShutdownCritical();
        } else if (to_starts.count(s->name())) {
            if (auto result = s->Start(); !result) {
                LOG(ERROR) << "Could not start shutdown 'to_start' service '" << s->name()
                           << "': " << result.error();
            }
            s->SetShutdownCritical();
        } else if (s->IsShutdownCritical()) {
            // Start shutdown critical service if not started.
            if (auto result = s->Start(); !result) {
                LOG(ERROR) << "Could not start shutdown critical service '" << s->name()
                           << "': " << result.error();
            }
        }
    }

    // remaining operations (specifically fsck) may take a substantial duration
    if (cmd == ANDROID_RB_POWEROFF || is_thermal_shutdown) {
        TurnOffBacklight();
    }

    Service* bootAnim = ServiceList::GetInstance().FindService("bootanim");
    Service* surfaceFlinger = ServiceList::GetInstance().FindService("surfaceflinger");
    if (bootAnim != nullptr && surfaceFlinger != nullptr && surfaceFlinger->IsRunning()) {
        // will not check animation class separately
        for (const auto& service : ServiceList::GetInstance()) {
            if (service->classnames().count("animation")) service->SetShutdownCritical();
        }
    }

    // optional shutdown step
    // 1. terminate all services except shutdown critical ones. wait for delay to finish
    if (shutdown_timeout > 0ms) {
        LOG(INFO) << "terminating init services";

        // Ask all services to terminate except shutdown critical ones.
        for (const auto& s : ServiceList::GetInstance().services_in_shutdown_order()) {
            if (!s->IsShutdownCritical()) s->Terminate();
        }

        int service_count = 0;
        // Only wait up to half of timeout here
        auto termination_wait_timeout = shutdown_timeout / 2;
        while (t.duration() < termination_wait_timeout) {
            ReapAnyOutstandingChildren();

            service_count = 0;
            for (const auto& s : ServiceList::GetInstance()) {
                // Count the number of services running except shutdown critical.
                // Exclude the console as it will ignore the SIGTERM signal
                // and not exit.
                // Note: SVC_CONSOLE actually means "requires console" but
                // it is only used by the shell.
                if (!s->IsShutdownCritical() && s->pid() != 0 && (s->flags() & SVC_CONSOLE) == 0) {
                    service_count++;
                }
            }

            if (service_count == 0) {
                // All terminable services terminated. We can exit early.
                break;
            }

            // Wait a bit before recounting the number or running services.
            std::this_thread::sleep_for(50ms);
        }
        LOG(INFO) << "Terminating running services took " << t
                  << " with remaining services:" << service_count;
    }

    // minimum safety steps before restarting
    // 2. kill all services except ones that are necessary for the shutdown sequence.
    for (const auto& s : ServiceList::GetInstance().services_in_shutdown_order()) {
        if (!s->IsShutdownCritical()) s->Stop();
    }
    SubcontextTerminate();
    ReapAnyOutstandingChildren();

    // 3. send volume shutdown to vold
    Service* voldService = ServiceList::GetInstance().FindService("vold");
    if (voldService != nullptr && voldService->IsRunning()) {
        ShutdownVold();
        voldService->Stop();
    } else {
        LOG(INFO) << "vold not running, skipping vold shutdown";
    }
    // logcat stopped here
    for (const auto& s : ServiceList::GetInstance().services_in_shutdown_order()) {
        if (kill_after_apps.count(s->name())) s->Stop();
    }
    // 4. sync, try umount, and optionally run fsck for user shutdown
    {
        Timer sync_timer;
        LOG(INFO) << "sync() before umount...";
        sync();
        LOG(INFO) << "sync() before umount took" << sync_timer;
    }
    UmountStat stat = TryUmountAndFsck(runFsck, shutdown_timeout - t.duration());
    // Follow what linux shutdown is doing: one more sync with little bit delay
    {
        Timer sync_timer;
        LOG(INFO) << "sync() after umount...";
        sync();
        LOG(INFO) << "sync() after umount took" << sync_timer;
    }
    if (!is_thermal_shutdown) std::this_thread::sleep_for(100ms);
    LogShutdownTime(stat, &t);
    // Reboot regardless of umount status. If umount fails, fsck after reboot will fix it.
    RebootSystem(cmd, rebootTarget);
    abort();
}

bool HandlePowerctlMessage(const std::string& command) {
    unsigned int cmd = 0;
    std::vector<std::string> cmd_params = Split(command, ",");
    std::string reboot_target = "";
    bool run_fsck = false;
    bool command_invalid = false;

    if (cmd_params.size() > 3) {
        command_invalid = true;
    } else if (cmd_params[0] == "shutdown") {
        cmd = ANDROID_RB_POWEROFF;
        if (cmd_params.size() == 2) {
            if (cmd_params[1] == "userrequested") {
                // The shutdown reason is PowerManager.SHUTDOWN_USER_REQUESTED.
                // Run fsck once the file system is remounted in read-only mode.
                run_fsck = true;
            } else if (cmd_params[1] == "thermal") {
                // Turn off sources of heat immediately.
                TurnOffBacklight();
                // run_fsck is false to avoid delay
                cmd = ANDROID_RB_THERMOFF;
            }
        }
    } else if (cmd_params[0] == "reboot") {
        cmd = ANDROID_RB_RESTART2;
        if (cmd_params.size() >= 2) {
            reboot_target = cmd_params[1];
            // adb reboot fastboot should boot into bootloader for devices not
            // supporting logical partitions.
            if (reboot_target == "fastboot" &&
                !android::base::GetBoolProperty("ro.boot.logical_partitions", false)) {
                reboot_target = "bootloader";
            }
            // When rebooting to the bootloader notify the bootloader writing
            // also the BCB.
            if (reboot_target == "bootloader") {
                std::string err;
                if (!write_reboot_bootloader(&err)) {
                    LOG(ERROR) << "reboot-bootloader: Error writing "
                                  "bootloader_message: "
                               << err;
                }
            } else if (reboot_target == "sideload" || reboot_target == "sideload-auto-reboot" ||
                       reboot_target == "fastboot") {
                std::string arg = reboot_target == "sideload-auto-reboot" ? "sideload_auto_reboot"
                                                                          : reboot_target;
                const std::vector<std::string> options = {
                        "--" + arg,
                };
                std::string err;
                if (!write_bootloader_message(options, &err)) {
                    LOG(ERROR) << "Failed to set bootloader message: " << err;
                    return false;
                }
                reboot_target = "recovery";
            }

            // If there is an additional parameter, pass it along
            if ((cmd_params.size() == 3) && cmd_params[2].size()) {
                reboot_target += "," + cmd_params[2];
            }
        }
    } else {
        command_invalid = true;
    }
    if (command_invalid) {
        LOG(ERROR) << "powerctl: unrecognized command '" << command << "'";
        return false;
    }

    LOG(INFO) << "Clear action queue and start shutdown trigger";
    ActionManager::GetInstance().ClearQueue();
    // Queue shutdown trigger first
    ActionManager::GetInstance().QueueEventTrigger("shutdown");
    // Queue built-in shutdown_done
    auto shutdown_handler = [cmd, command, reboot_target, run_fsck](const BuiltinArguments&) {
        DoReboot(cmd, command, reboot_target, run_fsck);
        return Success();
    };
    ActionManager::GetInstance().QueueBuiltinAction(shutdown_handler, "shutdown_done");

    // Skip wait for prop if it is in progress
    ResetWaitForProp();

    // Clear EXEC flag if there is one pending
    for (const auto& s : ServiceList::GetInstance()) {
        s->UnSetExec();
    }

    return true;
}

}  // namespace init
}  // namespace android
