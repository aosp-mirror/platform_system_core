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
#include <dirent.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <mntent.h>
#include <selinux/selinux.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fs_mgr.h>
#include <logwrap/logwrap.h>

#include "log.h"
#include "property_service.h"
#include "reboot.h"
#include "service.h"
#include "util.h"

using android::base::StringPrintf;

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

    bool Umount() {
        int r = umount2(mnt_dir_.c_str(), 0);
        if (r == 0) {
            LOG(INFO) << "umounted " << mnt_fsname_ << ":" << mnt_dir_ << " opts " << mnt_opts_;
            return true;
        } else {
            PLOG(WARNING) << "cannot umount " << mnt_fsname_ << ":" << mnt_dir_ << " opts "
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
    static constexpr char OFF[] = "0";

    android::base::WriteStringToFile(OFF, "/sys/class/leds/lcd-backlight/brightness");

    static const char backlightDir[] = "/sys/class/backlight";
    std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(backlightDir), closedir);
    if (!dir) {
        return;
    }

    struct dirent* dp;
    while ((dp = readdir(dir.get())) != nullptr) {
        if (((dp->d_type != DT_DIR) && (dp->d_type != DT_LNK)) || (dp->d_name[0] == '.')) {
            continue;
        }

        std::string fileName = StringPrintf("%s/%s/brightness", backlightDir, dp->d_name);
        android::base::WriteStringToFile(OFF, fileName);
    }
}

static void ShutdownVold() {
    const char* vdc_argv[] = {"/system/bin/vdc", "volume", "shutdown"};
    int status;
    android_fork_execvp_ext(arraysize(vdc_argv), (char**)vdc_argv, &status, true, LOG_KLOG, true,
                            nullptr, nullptr, 0);
}

static void LogShutdownTime(UmountStat stat, Timer* t) {
    LOG(WARNING) << "powerctl_shutdown_time_ms:" << std::to_string(t->duration_ms()) << ":" << stat;
}

static void __attribute__((noreturn))
RebootSystem(unsigned int cmd, const std::string& rebootTarget) {
    LOG(INFO) << "Reboot ending, jumping to kernel";
    switch (cmd) {
        case ANDROID_RB_POWEROFF:
            reboot(RB_POWER_OFF);
            break;

        case ANDROID_RB_RESTART2:
            syscall(__NR_reboot, LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                    LINUX_REBOOT_CMD_RESTART2, rebootTarget.c_str());
            break;

        case ANDROID_RB_THERMOFF:
            reboot(RB_POWER_OFF);
            break;
    }
    // In normal case, reboot should not return.
    PLOG(FATAL) << "reboot call returned";
    abort();
}

/* Find all read+write block devices and emulated devices in /proc/mounts
 * and add them to correpsponding list.
 */
static bool FindPartitionsToUmount(std::vector<MountEntry>* blockDevPartitions,
                                   std::vector<MountEntry>* emulatedPartitions, bool dump) {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "r"), endmntent);
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
            blockDevPartitions->emplace(blockDevPartitions->begin(), *mentry);
        } else if (MountEntry::IsEmulatedDevice(*mentry)) {
            emulatedPartitions->emplace(emulatedPartitions->begin(), *mentry);
        }
    }
    return true;
}

static void DumpUmountDebuggingInfo() {
    int status;
    if (!security_getenforce()) {
        LOG(INFO) << "Run lsof";
        const char* lsof_argv[] = {"/system/bin/lsof"};
        android_fork_execvp_ext(arraysize(lsof_argv), (char**)lsof_argv, &status, true, LOG_KLOG,
                                true, nullptr, nullptr, 0);
    }
    FindPartitionsToUmount(nullptr, nullptr, true);
}

static UmountStat UmountPartitions(int timeoutMs) {
    Timer t;
    UmountStat stat = UMOUNT_STAT_TIMEOUT;
    int retry = 0;
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
            stat = UMOUNT_STAT_SUCCESS;
            break;
        }
        if ((timeoutMs < t.duration_ms()) && retry > 0) {  // try umount at least once
            stat = UMOUNT_STAT_TIMEOUT;
            break;
        }
        if (emulated_devices.size() > 0 &&
            std::all_of(emulated_devices.begin(), emulated_devices.end(),
                        [](auto& entry) { return entry.Umount(); })) {
            sync();
        }
        for (auto& entry : block_devices) {
            entry.Umount();
        }
        retry++;
        std::this_thread::sleep_for(100ms);
    }
    return stat;
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
static UmountStat TryUmountAndFsck(bool runFsck, int timeoutMs) {
    Timer t;
    std::vector<MountEntry> block_devices;
    std::vector<MountEntry> emulated_devices;

    TurnOffBacklight();  // this part can take time. save power.

    if (runFsck && !FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
        return UMOUNT_STAT_ERROR;
    }

    UmountStat stat = UmountPartitions(timeoutMs - t.duration_ms());
    if (stat != UMOUNT_STAT_SUCCESS) {
        LOG(INFO) << "umount timeout, last resort, kill all and try";
        if (DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo();
        KillAllProcesses();
        // even if it succeeds, still it is timeout and do not run fsck with all processes killed
        UmountPartitions(0);
        if (DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo();
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

static void __attribute__((noreturn)) DoThermalOff() {
    LOG(WARNING) << "Thermal system shutdown";
    sync();
    RebootSystem(ANDROID_RB_THERMOFF, "");
    abort();
}

void DoReboot(unsigned int cmd, const std::string& reason, const std::string& rebootTarget,
              bool runFsck) {
    Timer t;
    LOG(INFO) << "Reboot start, reason: " << reason << ", rebootTarget: " << rebootTarget;

    android::base::WriteStringToFile(StringPrintf("%s\n", reason.c_str()), LAST_REBOOT_REASON_FILE);

    if (cmd == ANDROID_RB_THERMOFF) {  // do not wait if it is thermal
        DoThermalOff();
        abort();
    }

    /* TODO update default waiting time based on usage data */
    constexpr unsigned int shutdownTimeoutDefault = 10;
    unsigned int shutdownTimeout = shutdownTimeoutDefault;
    if (SHUTDOWN_ZERO_TIMEOUT) {  // eng build
        shutdownTimeout = 0;
    } else {
        shutdownTimeout =
            android::base::GetUintProperty("ro.build.shutdown_timeout", shutdownTimeoutDefault);
    }
    LOG(INFO) << "Shutdown timeout: " << shutdownTimeout;

    // keep debugging tools until non critical ones are all gone.
    const std::set<std::string> kill_after_apps{"tombstoned", "logd", "adbd"};
    // watchdogd is a vendor specific component but should be alive to complete shutdown safely.
    const std::set<std::string> to_starts{"watchdogd", "vold"};
    ServiceManager::GetInstance().ForEachService([&kill_after_apps, &to_starts](Service* s) {
        if (kill_after_apps.count(s->name())) {
            s->SetShutdownCritical();
        } else if (to_starts.count(s->name())) {
            s->Start();
            s->SetShutdownCritical();
        }
    });

    Service* bootAnim = ServiceManager::GetInstance().FindServiceByName("bootanim");
    Service* surfaceFlinger = ServiceManager::GetInstance().FindServiceByName("surfaceflinger");
    if (bootAnim != nullptr && surfaceFlinger != nullptr && surfaceFlinger->IsRunning()) {
        property_set("service.bootanim.exit", "0");
        // Could be in the middle of animation. Stop and start so that it can pick
        // up the right mode.
        bootAnim->Stop();
        // start all animation classes if stopped.
        ServiceManager::GetInstance().ForEachServiceInClass("animation", [](Service* s) {
            s->Start();
            s->SetShutdownCritical();  // will not check animation class separately
        });
        bootAnim->Start();
        surfaceFlinger->SetShutdownCritical();
        bootAnim->SetShutdownCritical();
    }

    // optional shutdown step
    // 1. terminate all services except shutdown critical ones. wait for delay to finish
    if (shutdownTimeout > 0) {
        LOG(INFO) << "terminating init services";

        // Ask all services to terminate except shutdown critical ones.
        ServiceManager::GetInstance().ForEachService([](Service* s) {
            if (!s->IsShutdownCritical()) s->Terminate();
        });

        int service_count = 0;
        // Up to half as long as shutdownTimeout or 3 seconds, whichever is lower.
        unsigned int terminationWaitTimeout = std::min<unsigned int>((shutdownTimeout + 1) / 2, 3);
        while (t.duration_s() < terminationWaitTimeout) {
            ServiceManager::GetInstance().ReapAnyOutstandingChildren();

            service_count = 0;
            ServiceManager::GetInstance().ForEachService([&service_count](Service* s) {
                // Count the number of services running except shutdown critical.
                // Exclude the console as it will ignore the SIGTERM signal
                // and not exit.
                // Note: SVC_CONSOLE actually means "requires console" but
                // it is only used by the shell.
                if (!s->IsShutdownCritical() && s->pid() != 0 && (s->flags() & SVC_CONSOLE) == 0) {
                    service_count++;
                }
            });

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
    ServiceManager::GetInstance().ForEachService([](Service* s) {
        if (!s->IsShutdownCritical()) s->Stop();
    });
    ServiceManager::GetInstance().ReapAnyOutstandingChildren();

    // 3. send volume shutdown to vold
    Service* voldService = ServiceManager::GetInstance().FindServiceByName("vold");
    if (voldService != nullptr && voldService->IsRunning()) {
        ShutdownVold();
        voldService->Stop();
    } else {
        LOG(INFO) << "vold not running, skipping vold shutdown";
    }
    // logcat stopped here
    ServiceManager::GetInstance().ForEachService([&kill_after_apps](Service* s) {
        if (kill_after_apps.count(s->name())) s->Stop();
    });
    // 4. sync, try umount, and optionally run fsck for user shutdown
    sync();
    UmountStat stat = TryUmountAndFsck(runFsck, shutdownTimeout * 1000 - t.duration_ms());
    // Follow what linux shutdown is doing: one more sync with little bit delay
    sync();
    std::this_thread::sleep_for(100ms);
    LogShutdownTime(stat, &t);
    // Reboot regardless of umount status. If umount fails, fsck after reboot will fix it.
    RebootSystem(cmd, rebootTarget);
    abort();
}
