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
#include <mntent.h>
#include <sys/cdefs.h>
#include <sys/mount.h>
#include <sys/quota.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <cutils/partition_utils.h>
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
    explicit MountEntry(const mntent& entry, bool isMounted = true)
        : mnt_fsname_(entry.mnt_fsname),
          mnt_dir_(entry.mnt_dir),
          mnt_type_(entry.mnt_type),
          is_mounted_(isMounted) {}

    bool IsF2Fs() const { return mnt_type_ == "f2fs"; }

    bool IsExt4() const { return mnt_type_ == "ext4"; }

    bool is_mounted() const { return is_mounted_; }

    void set_is_mounted() { is_mounted_ = false; }

    const std::string& mnt_fsname() const { return mnt_fsname_; }

    const std::string& mnt_dir() const { return mnt_dir_; }

    static bool IsBlockDevice(const struct mntent& mntent) {
        return android::base::StartsWith(mntent.mnt_fsname, "/dev/block");
    }

    static bool IsEmulatedDevice(const struct mntent& mntent) {
        static const std::string SDCARDFS_NAME = "sdcardfs";
        return android::base::StartsWith(mntent.mnt_fsname, "/data/") &&
               SDCARDFS_NAME == mntent.mnt_type;
    }

  private:
    std::string mnt_fsname_;
    std::string mnt_dir_;
    std::string mnt_type_;
    bool is_mounted_;
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

static void DoFsck(const MountEntry& entry) {
    static constexpr int UNMOUNT_CHECK_TIMES = 10;

    if (!entry.IsF2Fs() && !entry.IsExt4()) return;

    int count = 0;
    while (count++ < UNMOUNT_CHECK_TIMES) {
        int fd = TEMP_FAILURE_RETRY(open(entry.mnt_fsname().c_str(), O_RDONLY | O_EXCL));
        if (fd >= 0) {
            /* |entry->mnt_dir| has sucessfully been unmounted. */
            close(fd);
            break;
        } else if (errno == EBUSY) {
            // Some processes using |entry->mnt_dir| are still alive. Wait for a
            // while then retry.
            std::this_thread::sleep_for(5000ms / UNMOUNT_CHECK_TIMES);
            continue;
        } else {
            /* Cannot open the device. Give up. */
            return;
        }
    }

    // NB: With watchdog still running, there is no cap on the time it takes
    // to complete the fsck, from the users perspective the device graphics
    // and responses are locked-up and they may choose to hold the power
    // button in frustration if it drags out.

    int st;
    if (entry.IsF2Fs()) {
        const char* f2fs_argv[] = {
            "/system/bin/fsck.f2fs", "-f", entry.mnt_fsname().c_str(),
        };
        android_fork_execvp_ext(arraysize(f2fs_argv), (char**)f2fs_argv, &st, true, LOG_KLOG, true,
                                nullptr, nullptr, 0);
    } else if (entry.IsExt4()) {
        const char* ext4_argv[] = {
            "/system/bin/e2fsck", "-f", "-y", entry.mnt_fsname().c_str(),
        };
        android_fork_execvp_ext(arraysize(ext4_argv), (char**)ext4_argv, &st, true, LOG_KLOG, true,
                                nullptr, nullptr, 0);
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

static void DoSync() {
    // quota sync is not done by sync call, so should be done separately.
    // quota sync is in VFS level, so do it before sync, which goes down to fs level.
    int r = quotactl(QCMD(Q_SYNC, 0), nullptr, 0 /* do not care */, 0 /* do not care */);
    if (r < 0) {
        PLOG(ERROR) << "quotactl failed";
    }
    sync();
}

/* Find all read+write block devices and emulated devices in /proc/mounts
 * and add them to correpsponding list.
 */
static bool FindPartitionsToUmount(std::vector<MountEntry>* blockDevPartitions,
                                   std::vector<MountEntry>* emulatedPartitions) {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "r"), endmntent);
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return false;
    }
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        if (MountEntry::IsBlockDevice(*mentry) && hasmntopt(mentry, "rw")) {
            blockDevPartitions->emplace_back(*mentry);
        } else if (MountEntry::IsEmulatedDevice(*mentry)) {
            emulatedPartitions->emplace_back(*mentry);
        }
    }
    return true;
}

static bool UmountPartitions(std::vector<MountEntry>* partitions, int maxRetry, int flags) {
    static constexpr int SLEEP_AFTER_RETRY_US = 100000;

    bool umountDone;
    int retryCounter = 0;

    while (true) {
        umountDone = true;
        for (auto& entry : *partitions) {
            if (entry.is_mounted()) {
                int r = umount2(entry.mnt_dir().c_str(), flags);
                if (r == 0) {
                    entry.set_is_mounted();
                    LOG(INFO) << StringPrintf("umounted %s, flags:0x%x", entry.mnt_fsname().c_str(),
                                              flags);
                } else {
                    umountDone = false;
                    PLOG(WARNING) << StringPrintf("cannot umount %s, flags:0x%x",
                                                  entry.mnt_fsname().c_str(), flags);
                }
            }
        }
        if (umountDone) break;
        retryCounter++;
        if (retryCounter >= maxRetry) break;
        usleep(SLEEP_AFTER_RETRY_US);
    }
    return umountDone;
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
    std::vector<MountEntry> emulatedPartitions;
    std::vector<MountEntry> blockDevRwPartitions;

    TurnOffBacklight();  // this part can take time. save power.

    if (!FindPartitionsToUmount(&blockDevRwPartitions, &emulatedPartitions)) {
        return UMOUNT_STAT_ERROR;
    }
    if (emulatedPartitions.size() > 0) {
        LOG(WARNING) << "emulated partitions still exist, will umount";
        /* Pending writes in emulated partitions can fail umount. After a few trials, detach
         * it so that it can be umounted when all writes are done.
         */
        if (!UmountPartitions(&emulatedPartitions, 1, 0)) {
            UmountPartitions(&emulatedPartitions, 1, MNT_DETACH);
        }
    }
    DoSync();  // emulated partition change can lead to update
    UmountStat stat = UMOUNT_STAT_SUCCESS;
    /* data partition needs all pending writes to be completed and all emulated partitions
     * umounted. If umount failed in the above step, it DETACH is requested, so umount can
     * still happen while waiting for /data. If the current waiting is not good enough, give
     * up and leave it to e2fsck after reboot to fix it.
     */
    int remainingTimeMs = timeoutMs - t.duration_ms();
    // each retry takes 100ms, and run at least once.
    int retry = std::max(remainingTimeMs / 100, 1);
    if (!UmountPartitions(&blockDevRwPartitions, retry, 0)) {
        /* Last resort, kill all and try again */
        LOG(WARNING) << "umount still failing, trying kill all";
        KillAllProcesses();
        DoSync();
        if (!UmountPartitions(&blockDevRwPartitions, 1, 0)) {
            stat = UMOUNT_STAT_TIMEOUT;
        }
    }
    // fsck part is excluded from timeout check. It only runs for user initiated shutdown
    // and should not affect reboot time.
    if (stat == UMOUNT_STAT_SUCCESS && runFsck) {
        for (auto& entry : blockDevRwPartitions) {
            DoFsck(entry);
        }
    }

    return stat;
}

static void __attribute__((noreturn)) DoThermalOff() {
    LOG(WARNING) << "Thermal system shutdown";
    DoSync();
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

    std::string timeout = property_get("ro.build.shutdown_timeout");
    /* TODO update default waiting time based on usage data */
    unsigned int shutdownTimeout = 10;  // default value
    if (android::base::ParseUint(timeout, &shutdownTimeout)) {
        LOG(INFO) << "ro.build.shutdown_timeout set:" << shutdownTimeout;
    }

    static const constexpr char* shutdown_critical_services[] = {"vold", "watchdogd"};
    for (const char* name : shutdown_critical_services) {
        Service* s = ServiceManager::GetInstance().FindServiceByName(name);
        if (s == nullptr) {
            LOG(WARNING) << "Shutdown critical service not found:" << name;
            continue;
        }
        s->Start();  // make sure that it is running.
        s->SetShutdownCritical();
    }
    // optional shutdown step
    // 1. terminate all services except shutdown critical ones. wait for delay to finish
    if (shutdownTimeout > 0) {
        LOG(INFO) << "terminating init services";
        // tombstoned can write to data when other services are killed. so finish it first.
        static const constexpr char* first_to_kill[] = {"tombstoned"};
        for (const char* name : first_to_kill) {
            Service* s = ServiceManager::GetInstance().FindServiceByName(name);
            if (s != nullptr) s->Stop();
        }

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
    } else {
        LOG(INFO) << "vold not running, skipping vold shutdown";
    }
    // 4. sync, try umount, and optionally run fsck for user shutdown
    DoSync();
    UmountStat stat = TryUmountAndFsck(runFsck, shutdownTimeout * 1000 - t.duration_ms());
    LogShutdownTime(stat, &t);
    // Reboot regardless of umount status. If umount fails, fsck after reboot will fix it.
    RebootSystem(cmd, rebootTarget);
    abort();
}
