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
#include <linux/f2fs.h>
#include <linux/fs.h>
#include <linux/loop.h>
#include <mntent.h>
#include <semaphore.h>
#include <stdlib.h>
#include <sys/cdefs.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/swap.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <chrono>
#include <memory>
#include <set>
#include <thread>
#include <vector>

#include <InitProperties.sysprop.h>
#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <fs_mgr.h>
#include <libsnapshot/snapshot.h>
#include <logwrap/logwrap.h>
#include <private/android_filesystem_config.h>
#include <selinux/selinux.h>

#include "action.h"
#include "action_manager.h"
#include "builtin_arguments.h"
#include "init.h"
#include "mount_namespace.h"
#include "property_service.h"
#include "reboot_utils.h"
#include "service.h"
#include "service_list.h"
#include "sigchld_handler.h"
#include "util.h"

using namespace std::literals;

using android::base::boot_clock;
using android::base::GetBoolProperty;
using android::base::GetUintProperty;
using android::base::SetProperty;
using android::base::Split;
using android::base::Timer;
using android::base::unique_fd;
using android::base::WaitForProperty;
using android::base::WriteStringToFile;

namespace android {
namespace init {

static bool shutting_down = false;

static const std::set<std::string> kDebuggingServices{"tombstoned", "logd", "adbd", "console"};

static void PersistRebootReason(const char* reason, bool write_to_property) {
    if (write_to_property) {
        SetProperty(LAST_REBOOT_REASON_PROPERTY, reason);
    }
    auto fd = unique_fd(TEMP_FAILURE_RETRY(open(
            LAST_REBOOT_REASON_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_BINARY, 0666)));
    if (!fd.ok()) {
        PLOG(ERROR) << "Could not open '" << LAST_REBOOT_REASON_FILE
                    << "' to persist reboot reason";
        return;
    }
    WriteStringToFd(reason, fd);
    fsync(fd.get());
}

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
                    "/system/bin/fsck.f2fs",
                    "-a",
                    mnt_fsname_.c_str(),
            };
            logwrap_fork_execvp(arraysize(f2fs_argv), f2fs_argv, &st, false, LOG_KLOG, true,
                                nullptr);
        } else if (IsExt4()) {
            const char* ext4_argv[] = {
                    "/system/bin/e2fsck",
                    "-y",
                    mnt_fsname_.c_str(),
            };
            logwrap_fork_execvp(arraysize(ext4_argv), ext4_argv, &st, false, LOG_KLOG, true,
                                nullptr);
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
    if (auto result = service->Start(); !result.ok()) {
        LOG(WARNING) << "Could not start blank_screen service: " << result.error();
    }
}

static Result<void> CallVdc(const std::string& system, const std::string& cmd) {
    LOG(INFO) << "Calling /system/bin/vdc " << system << " " << cmd;
    const char* vdc_argv[] = {"/system/bin/vdc", system.c_str(), cmd.c_str()};
    int status;
    if (logwrap_fork_execvp(arraysize(vdc_argv), vdc_argv, &status, false, LOG_KLOG, true,
                            nullptr) != 0) {
        return ErrnoError() << "Failed to call '/system/bin/vdc " << system << " " << cmd << "'";
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return {};
    }
    return Error() << "'/system/bin/vdc " << system << " " << cmd << "' failed : " << status;
}

static void LogShutdownTime(UmountStat stat, Timer* t) {
    LOG(WARNING) << "powerctl_shutdown_time_ms:" << std::to_string(t->duration().count()) << ":"
                 << stat;
}

static bool IsDataMounted(const std::string& fstype) {
    std::unique_ptr<std::FILE, int (*)(std::FILE*)> fp(setmntent("/proc/mounts", "re"), endmntent);
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to open /proc/mounts";
        return false;
    }
    mntent* mentry;
    while ((mentry = getmntent(fp.get())) != nullptr) {
        if (mentry->mnt_dir == "/data"s) {
            return fstype == "*" || mentry->mnt_type == fstype;
        }
    }
    return false;
}

// Find all read+write block devices and emulated devices in /proc/mounts and add them to
// the correpsponding list.
static bool FindPartitionsToUmount(std::vector<MountEntry>* block_dev_partitions,
                                   std::vector<MountEntry>* emulated_partitions, bool dump) {
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
                block_dev_partitions->emplace(block_dev_partitions->begin(), *mentry);
            }
        } else if (MountEntry::IsEmulatedDevice(*mentry)) {
            emulated_partitions->emplace(emulated_partitions->begin(), *mentry);
        }
    }
    return true;
}

static void DumpUmountDebuggingInfo() {
    int status;
    if (!security_getenforce()) {
        LOG(INFO) << "Run lsof";
        const char* lsof_argv[] = {"/system/bin/lsof"};
        logwrap_fork_execvp(arraysize(lsof_argv), lsof_argv, &status, false, LOG_KLOG, true,
                            nullptr);
    }
    FindPartitionsToUmount(nullptr, nullptr, true);
    // dump current CPU stack traces and uninterruptible tasks
    WriteStringToFile("l", PROC_SYSRQ);
    WriteStringToFile("w", PROC_SYSRQ);
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

static void KillAllProcesses() {
    WriteStringToFile("i", PROC_SYSRQ);
}

// Create reboot/shutdwon monitor thread
void RebootMonitorThread(unsigned int cmd, const std::string& reboot_target,
                         sem_t* reboot_semaphore, std::chrono::milliseconds shutdown_timeout,
                         bool* reboot_monitor_run) {
    unsigned int remaining_shutdown_time = 0;

    // 300 seconds more than the timeout passed to the thread as there is a final Umount pass
    // after the timeout is reached.
    constexpr unsigned int shutdown_watchdog_timeout_default = 300;
    auto shutdown_watchdog_timeout = android::base::GetUintProperty(
            "ro.build.shutdown.watchdog.timeout", shutdown_watchdog_timeout_default);
    remaining_shutdown_time = shutdown_watchdog_timeout + shutdown_timeout.count() / 1000;

    while (*reboot_monitor_run == true) {
        if (TEMP_FAILURE_RETRY(sem_wait(reboot_semaphore)) == -1) {
            LOG(ERROR) << "sem_wait failed and exit RebootMonitorThread()";
            return;
        }

        timespec shutdown_timeout_timespec;
        if (clock_gettime(CLOCK_MONOTONIC, &shutdown_timeout_timespec) == -1) {
            LOG(ERROR) << "clock_gettime() fail! exit RebootMonitorThread()";
            return;
        }

        // If there are some remaining shutdown time left from previous round, we use
        // remaining time here.
        shutdown_timeout_timespec.tv_sec += remaining_shutdown_time;

        LOG(INFO) << "shutdown_timeout_timespec.tv_sec: " << shutdown_timeout_timespec.tv_sec;

        int sem_return = 0;
        while ((sem_return = sem_timedwait_monotonic_np(reboot_semaphore,
                                                        &shutdown_timeout_timespec)) == -1 &&
               errno == EINTR) {
        }

        if (sem_return == -1) {
            LOG(ERROR) << "Reboot thread timed out";

            if (android::base::GetBoolProperty("ro.debuggable", false) == true) {
                if (false) {
                    // SEPolicy will block debuggerd from running and this is intentional.
                    // But these lines are left to be enabled during debugging.
                    LOG(INFO) << "Try to dump init process call trace:";
                    const char* vdc_argv[] = {"/system/bin/debuggerd", "-b", "1"};
                    int status;
                    logwrap_fork_execvp(arraysize(vdc_argv), vdc_argv, &status, false, LOG_KLOG,
                                        true, nullptr);
                }
                LOG(INFO) << "Show stack for all active CPU:";
                WriteStringToFile("l", PROC_SYSRQ);

                LOG(INFO) << "Show tasks that are in disk sleep(uninterruptable sleep), which are "
                             "like "
                             "blocked in mutex or hardware register access:";
                WriteStringToFile("w", PROC_SYSRQ);
            }

            // In shutdown case,notify kernel to sync and umount fs to read-only before shutdown.
            if (cmd == ANDROID_RB_POWEROFF || cmd == ANDROID_RB_THERMOFF) {
                WriteStringToFile("s", PROC_SYSRQ);

                WriteStringToFile("u", PROC_SYSRQ);

                RebootSystem(cmd, reboot_target);
            }

            LOG(ERROR) << "Trigger crash at last!";
            WriteStringToFile("c", PROC_SYSRQ);
        } else {
            timespec current_time_timespec;

            if (clock_gettime(CLOCK_MONOTONIC, &current_time_timespec) == -1) {
                LOG(ERROR) << "clock_gettime() fail! exit RebootMonitorThread()";
                return;
            }

            remaining_shutdown_time =
                    shutdown_timeout_timespec.tv_sec - current_time_timespec.tv_sec;

            LOG(INFO) << "remaining_shutdown_time: " << remaining_shutdown_time;
        }
    }
}

/* Try umounting all emulated file systems R/W block device cfile systems.
 * This will just try umount and give it up if it fails.
 * For fs like ext4, this is ok as file system will be marked as unclean shutdown
 * and necessary check can be done at the next reboot.
 * For safer shutdown, caller needs to make sure that
 * all processes / emulated partition for the target fs are all cleaned-up.
 *
 * return true when umount was successful. false when timed out.
 */
static UmountStat TryUmountAndFsck(unsigned int cmd, bool run_fsck,
                                   std::chrono::milliseconds timeout, sem_t* reboot_semaphore) {
    Timer t;
    std::vector<MountEntry> block_devices;
    std::vector<MountEntry> emulated_devices;

    if (run_fsck && !FindPartitionsToUmount(&block_devices, &emulated_devices, false)) {
        return UMOUNT_STAT_ERROR;
    }
    auto sm = snapshot::SnapshotManager::New();
    bool ota_update_in_progress = false;
    if (sm->IsUserspaceSnapshotUpdateInProgress()) {
        LOG(INFO) << "OTA update in progress";
        ota_update_in_progress = true;
    }
    UmountStat stat = UmountPartitions(timeout - t.duration());
    if (stat != UMOUNT_STAT_SUCCESS) {
        LOG(INFO) << "umount timeout, last resort, kill all and try";
        if (DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo();
        // Since umount timedout, we will try to kill all processes
        // and do one more attempt to umount the partitions.
        //
        // However, if OTA update is in progress, we don't want
        // to kill the snapuserd daemon as the daemon will
        // be serving I/O requests. Killing the daemon will
        // end up with I/O failures. If the update is in progress,
        // we will just return the umount failure status immediately.
        // This is ok, given the fact that killing the processes
        // and doing an umount is just a last effort. We are
        // still not doing fsck when all processes are killed.
        //
        if (ota_update_in_progress) {
            return stat;
        }
        KillAllProcesses();
        // even if it succeeds, still it is timeout and do not run fsck with all processes killed
        UmountStat st = UmountPartitions(0ms);
        if ((st != UMOUNT_STAT_SUCCESS) && DUMP_ON_UMOUNT_FAILURE) DumpUmountDebuggingInfo();
    }

    if (stat == UMOUNT_STAT_SUCCESS && run_fsck) {
        LOG(INFO) << "Pause reboot monitor thread before fsck";
        sem_post(reboot_semaphore);

        // fsck part is excluded from timeout check. It only runs for user initiated shutdown
        // and should not affect reboot time.
        for (auto& entry : block_devices) {
            entry.DoFsck();
        }

        LOG(INFO) << "Resume reboot monitor thread after fsck";
        sem_post(reboot_semaphore);
    }
    return stat;
}

// zram is able to use backing device on top of a loopback device.
// In order to unmount /data successfully, we have to kill the loopback device first
#define ZRAM_DEVICE       "/dev/block/zram0"
#define ZRAM_RESET        "/sys/block/zram0/reset"
#define ZRAM_BACK_DEV     "/sys/block/zram0/backing_dev"
#define ZRAM_INITSTATE    "/sys/block/zram0/initstate"
static Result<void> KillZramBackingDevice() {
    std::string zram_initstate;
    if (!android::base::ReadFileToString(ZRAM_INITSTATE, &zram_initstate)) {
        return ErrnoError() << "Failed to read " << ZRAM_INITSTATE;
    }

    zram_initstate.erase(zram_initstate.length() - 1);
    if (zram_initstate == "0") {
        LOG(INFO) << "Zram has not been swapped on";
        return {};
    }

    if (access(ZRAM_BACK_DEV, F_OK) != 0 && errno == ENOENT) {
        LOG(INFO) << "No zram backing device configured";
        return {};
    }
    std::string backing_dev;
    if (!android::base::ReadFileToString(ZRAM_BACK_DEV, &backing_dev)) {
        return ErrnoError() << "Failed to read " << ZRAM_BACK_DEV;
    }

    // cut the last "\n"
    backing_dev.erase(backing_dev.length() - 1);

    if (android::base::StartsWith(backing_dev, "none")) {
        LOG(INFO) << "No zram backing device configured";
        return {};
    }

    // shutdown zram handle
    Timer swap_timer;
    LOG(INFO) << "swapoff() start...";
    if (swapoff(ZRAM_DEVICE) == -1) {
        return ErrnoError() << "zram_backing_dev: swapoff (" << backing_dev << ")"
                            << " failed";
    }
    LOG(INFO) << "swapoff() took " << swap_timer;

    if (!WriteStringToFile("1", ZRAM_RESET)) {
        return Error() << "zram_backing_dev: reset (" << backing_dev << ")"
                       << " failed";
    }

    if (!android::base::StartsWith(backing_dev, "/dev/block/loop")) {
        LOG(INFO) << backing_dev << " is not a loop device. Exiting early";
        return {};
    }

    // clear loopback device
    unique_fd loop(TEMP_FAILURE_RETRY(open(backing_dev.c_str(), O_RDWR | O_CLOEXEC)));
    if (loop.get() < 0) {
        return ErrnoError() << "zram_backing_dev: open(" << backing_dev << ")"
                            << " failed";
    }

    if (ioctl(loop.get(), LOOP_CLR_FD, 0) < 0) {
        return ErrnoError() << "zram_backing_dev: loop_clear (" << backing_dev << ")"
                            << " failed";
    }
    LOG(INFO) << "zram_backing_dev: `" << backing_dev << "` is cleared successfully.";
    return {};
}

// Stops given services, waits for them to be stopped for |timeout| ms.
// If terminate is true, then SIGTERM is sent to services, otherwise SIGKILL is sent.
// Note that services are stopped in order given by |ServiceList::services_in_shutdown_order|
// function.
static void StopServices(const std::set<std::string>& services, std::chrono::milliseconds timeout,
                         bool terminate) {
    LOG(INFO) << "Stopping " << services.size() << " services by sending "
              << (terminate ? "SIGTERM" : "SIGKILL");
    std::vector<pid_t> pids;
    pids.reserve(services.size());
    for (const auto& s : ServiceList::GetInstance().services_in_shutdown_order()) {
        if (services.count(s->name()) == 0) {
            continue;
        }
        if (s->pid() > 0) {
            pids.push_back(s->pid());
        }
        if (terminate) {
            s->Terminate();
        } else {
            s->Stop();
        }
    }
    if (timeout > 0ms) {
        WaitToBeReaped(Service::GetSigchldFd(), pids, timeout);
    } else {
        // Even if we don't to wait for services to stop, we still optimistically reap zombies.
        ReapAnyOutstandingChildren();
    }
}

// Like StopServices, but also logs all the services that failed to stop after the provided timeout.
// Returns number of violators.
int StopServicesAndLogViolations(const std::set<std::string>& services,
                                 std::chrono::milliseconds timeout, bool terminate) {
    StopServices(services, timeout, terminate);
    int still_running = 0;
    for (const auto& s : ServiceList::GetInstance()) {
        if (s->IsRunning() && services.count(s->name())) {
            LOG(ERROR) << "[service-misbehaving] : service '" << s->name() << "' is still running "
                       << timeout.count() << "ms after receiving "
                       << (terminate ? "SIGTERM" : "SIGKILL");
            still_running++;
        }
    }
    return still_running;
}

static Result<void> UnmountAllApexes() {
    // don't need to unmount because apexd doesn't use /data in Microdroid
    if (IsMicrodroid()) {
        return {};
    }

    const char* args[] = {"/system/bin/apexd", "--unmount-all"};
    int status;
    if (logwrap_fork_execvp(arraysize(args), args, &status, false, LOG_KLOG, true, nullptr) != 0) {
        return ErrnoError() << "Failed to call '/system/bin/apexd --unmount-all'";
    }
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return {};
    }
    return Error() << "'/system/bin/apexd --unmount-all' failed : " << status;
}

//* Reboot / shutdown the system.
// cmd ANDROID_RB_* as defined in android_reboot.h
// reason Reason string like "reboot", "shutdown,userrequested"
// reboot_target Reboot target string like "bootloader". Otherwise, it should be an empty string.
// run_fsck Whether to run fsck after umount is done.
//
static void DoReboot(unsigned int cmd, const std::string& reason, const std::string& reboot_target,
                     bool run_fsck) {
    Timer t;
    LOG(INFO) << "Reboot start, reason: " << reason << ", reboot_target: " << reboot_target;

    bool is_thermal_shutdown = cmd == ANDROID_RB_THERMOFF;

    auto shutdown_timeout = 0ms;
    if (!SHUTDOWN_ZERO_TIMEOUT) {
        constexpr unsigned int shutdown_timeout_default = 6;
        constexpr unsigned int max_thermal_shutdown_timeout = 3;
        auto shutdown_timeout_final = android::base::GetUintProperty("ro.build.shutdown_timeout",
                                                                     shutdown_timeout_default);
        if (is_thermal_shutdown && shutdown_timeout_final > max_thermal_shutdown_timeout) {
            shutdown_timeout_final = max_thermal_shutdown_timeout;
        }
        shutdown_timeout = std::chrono::seconds(shutdown_timeout_final);
    }
    LOG(INFO) << "Shutdown timeout: " << shutdown_timeout.count() << " ms";

    sem_t reboot_semaphore;
    if (sem_init(&reboot_semaphore, false, 0) == -1) {
        // These should never fail, but if they do, skip the graceful reboot and reboot immediately.
        LOG(ERROR) << "sem_init() fail and RebootSystem() return!";
        RebootSystem(cmd, reboot_target, reason);
    }

    // Start a thread to monitor init shutdown process
    LOG(INFO) << "Create reboot monitor thread.";
    bool reboot_monitor_run = true;
    std::thread reboot_monitor_thread(&RebootMonitorThread, cmd, reboot_target, &reboot_semaphore,
                                      shutdown_timeout, &reboot_monitor_run);
    reboot_monitor_thread.detach();

    // Start reboot monitor thread
    sem_post(&reboot_semaphore);

    // Ensure last reboot reason is reduced to canonical
    // alias reported in bootloader or system boot reason.
    size_t skip = 0;
    std::vector<std::string> reasons = Split(reason, ",");
    if (reasons.size() >= 2 && reasons[0] == "reboot" &&
        (reasons[1] == "recovery" || reasons[1] == "bootloader" || reasons[1] == "cold" ||
         reasons[1] == "hard" || reasons[1] == "warm")) {
        skip = strlen("reboot,");
    }
    PersistRebootReason(reason.c_str() + skip, true);

    // If /data isn't mounted then we can skip the extra reboot steps below, since we don't need to
    // worry about unmounting it.
    if (!IsDataMounted("*")) {
        sync();
        RebootSystem(cmd, reboot_target, reason);
        abort();
    }

    bool do_shutdown_animation = GetBoolProperty("ro.init.shutdown_animation", false);
    // watchdogd is a vendor specific component but should be alive to complete shutdown safely.
    const std::set<std::string> to_starts{"watchdogd"};
    std::set<std::string> stop_first;
    for (const auto& s : ServiceList::GetInstance()) {
        if (kDebuggingServices.count(s->name())) {
            // keep debugging tools until non critical ones are all gone.
            s->SetShutdownCritical();
        } else if (to_starts.count(s->name())) {
            if (auto result = s->Start(); !result.ok()) {
                LOG(ERROR) << "Could not start shutdown 'to_start' service '" << s->name()
                           << "': " << result.error();
            }
            s->SetShutdownCritical();
        } else if (do_shutdown_animation && s->classnames().count("animation") > 0) {
            // Need these for shutdown animations.
        } else if (s->IsShutdownCritical()) {
            // Start shutdown critical service if not started.
            if (auto result = s->Start(); !result.ok()) {
                LOG(ERROR) << "Could not start shutdown critical service '" << s->name()
                           << "': " << result.error();
            }
        } else {
            stop_first.insert(s->name());
        }
    }

    // remaining operations (specifically fsck) may take a substantial duration
    if (!do_shutdown_animation && (cmd == ANDROID_RB_POWEROFF || is_thermal_shutdown)) {
        TurnOffBacklight();
    }

    Service* boot_anim = ServiceList::GetInstance().FindService("bootanim");
    Service* surface_flinger = ServiceList::GetInstance().FindService("surfaceflinger");
    if (boot_anim != nullptr && surface_flinger != nullptr && surface_flinger->IsRunning()) {

        if (do_shutdown_animation) {
            SetProperty("service.bootanim.exit", "0");
            SetProperty("service.bootanim.progress", "0");
            // Could be in the middle of animation. Stop and start so that it can pick
            // up the right mode.
            boot_anim->Stop();
        }

        for (const auto& service : ServiceList::GetInstance()) {
            if (service->classnames().count("animation") == 0) {
                continue;
            }

            // start all animation classes if stopped.
            if (do_shutdown_animation) {
                service->Start();
            }
            service->SetShutdownCritical();  // will not check animation class separately
        }

        if (do_shutdown_animation) {
            boot_anim->Start();
            surface_flinger->SetShutdownCritical();
            boot_anim->SetShutdownCritical();
        }
    }

    // optional shutdown step
    // 1. terminate all services except shutdown critical ones. wait for delay to finish
    if (shutdown_timeout > 0ms) {
        StopServicesAndLogViolations(stop_first, shutdown_timeout / 2, true /* SIGTERM */);
    }
    // Send SIGKILL to ones that didn't terminate cleanly.
    StopServicesAndLogViolations(stop_first, 0ms, false /* SIGKILL */);
    SubcontextTerminate();
    // Reap subcontext pids.
    ReapAnyOutstandingChildren();

    // 3. send volume abort_fuse and volume shutdown to vold
    Service* vold_service = ServiceList::GetInstance().FindService("vold");
    if (vold_service != nullptr && vold_service->IsRunning()) {
        // Manually abort FUSE connections, since the FUSE daemon is already dead
        // at this point, and unmounting it might hang.
        CallVdc("volume", "abort_fuse");
        CallVdc("volume", "shutdown");
        vold_service->Stop();
    } else {
        LOG(INFO) << "vold not running, skipping vold shutdown";
    }
    // logcat stopped here
    StopServices(kDebuggingServices, 0ms, false /* SIGKILL */);
    // 4. sync, try umount, and optionally run fsck for user shutdown
    {
        Timer sync_timer;
        LOG(INFO) << "sync() before umount...";
        sync();
        LOG(INFO) << "sync() before umount took" << sync_timer;
    }
    // 5. drop caches and disable zram backing device, if exist
    KillZramBackingDevice();

    LOG(INFO) << "Ready to unmount apexes. So far shutdown sequence took " << t;
    // 6. unmount active apexes, otherwise they might prevent clean unmount of /data.
    if (auto ret = UnmountAllApexes(); !ret.ok()) {
        LOG(ERROR) << ret.error();
    }
    UmountStat stat =
            TryUmountAndFsck(cmd, run_fsck, shutdown_timeout - t.duration(), &reboot_semaphore);
    // Follow what linux shutdown is doing: one more sync with little bit delay
    {
        Timer sync_timer;
        LOG(INFO) << "sync() after umount...";
        sync();
        LOG(INFO) << "sync() after umount took" << sync_timer;
    }
    if (!is_thermal_shutdown) std::this_thread::sleep_for(100ms);
    LogShutdownTime(stat, &t);

    // Send signal to terminate reboot monitor thread.
    reboot_monitor_run = false;
    sem_post(&reboot_semaphore);

    // Reboot regardless of umount status. If umount fails, fsck after reboot will fix it.
    if (IsDataMounted("f2fs")) {
        uint32_t flag = F2FS_GOING_DOWN_FULLSYNC;
        unique_fd fd(TEMP_FAILURE_RETRY(open("/data", O_RDONLY)));
        int ret = ioctl(fd.get(), F2FS_IOC_SHUTDOWN, &flag);
        if (ret) {
            PLOG(ERROR) << "Shutdown /data: ";
        } else {
            LOG(INFO) << "Shutdown /data";
        }
    }
    RebootSystem(cmd, reboot_target, reason);
    abort();
}

static void EnterShutdown() {
    LOG(INFO) << "Entering shutdown mode";
    shutting_down = true;
    // Skip wait for prop if it is in progress
    ResetWaitForProp();
    // Clear EXEC flag if there is one pending
    for (const auto& s : ServiceList::GetInstance()) {
        s->UnSetExec();
    }
}

/**
 * Check if "command" field is set in bootloader message.
 *
 * If "command" field is broken (contains non-printable characters prior to
 * terminating zero), it will be zeroed.
 *
 * @param[in,out] boot Bootloader message (BCB) structure
 * @return true if "command" field is already set, and false if it's empty
 */
static bool CommandIsPresent(bootloader_message* boot) {
    if (boot->command[0] == '\0')
        return false;

    for (size_t i = 0; i < arraysize(boot->command); ++i) {
        if (boot->command[i] == '\0')
            return true;
        if (!isprint(boot->command[i]))
            break;
    }

    memset(boot->command, 0, sizeof(boot->command));
    return false;
}

void HandlePowerctlMessage(const std::string& command) {
    unsigned int cmd = 0;
    std::vector<std::string> cmd_params = Split(command, ",");
    std::string reboot_target = "";
    bool run_fsck = false;
    bool command_invalid = false;

    if (cmd_params[0] == "shutdown") {
        cmd = ANDROID_RB_POWEROFF;
        if (cmd_params.size() >= 2) {
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
            if (reboot_target == "userspace") {
                LOG(ERROR) << "Userspace reboot is deprecated.";
                return;
            }
            // adb reboot fastboot should boot into bootloader for devices not
            // supporting logical partitions.
            if (reboot_target == "fastboot" &&
                !android::base::GetBoolProperty("ro.boot.dynamic_partitions", false)) {
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
            } else if (reboot_target == "recovery") {
                bootloader_message boot = {};
                if (std::string err; !read_bootloader_message(&boot, &err)) {
                    LOG(ERROR) << "Failed to read bootloader message: " << err;
                }
                // Update the boot command field if it's empty, and preserve
                // the other arguments in the bootloader message.
                if (!CommandIsPresent(&boot)) {
                    strlcpy(boot.command, "boot-recovery", sizeof(boot.command));
                    if (std::string err; !write_bootloader_message(boot, &err)) {
                        LOG(ERROR) << "Failed to set bootloader message: " << err;
                        return;
                    }
                }
            } else if (std::find(cmd_params.begin(), cmd_params.end(), "quiescent")
                    != cmd_params.end()) { // Quiescent can be either subreason or details.
                bootloader_message boot = {};
                if (std::string err; !read_bootloader_message(&boot, &err)) {
                    LOG(ERROR) << "Failed to read bootloader message: " << err;
                }
                // Update the boot command field if it's empty, and preserve
                // the other arguments in the bootloader message.
                if (!CommandIsPresent(&boot)) {
                    strlcpy(boot.command, "boot-quiescent", sizeof(boot.command));
                    if (std::string err; !write_bootloader_message(boot, &err)) {
                        LOG(ERROR) << "Failed to set bootloader message: " << err;
                        return;
                    }
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
                    return;
                }
                reboot_target = "recovery";
            }

            // If there are additional parameter, pass them along
            for (size_t i = 2; (cmd_params.size() > i) && cmd_params[i].size(); ++i) {
                reboot_target += "," + cmd_params[i];
            }
        }
    } else {
        command_invalid = true;
    }
    if (command_invalid) {
        LOG(ERROR) << "powerctl: unrecognized command '" << command << "'";
        return;
    }

    // We do not want to process any messages (queue'ing triggers, shutdown messages, control
    // messages, etc) from properties during reboot.
    StopSendingMessages();

    LOG(INFO) << "Clear action queue and start shutdown trigger";
    ActionManager::GetInstance().ClearQueue();
    // Queue shutdown trigger first
    ActionManager::GetInstance().QueueEventTrigger("shutdown");
    // Queue built-in shutdown_done
    auto shutdown_handler = [cmd, command, reboot_target, run_fsck](const BuiltinArguments&) {
        DoReboot(cmd, command, reboot_target, run_fsck);
        return Result<void>{};
    };
    ActionManager::GetInstance().QueueBuiltinAction(shutdown_handler, "shutdown_done");

    EnterShutdown();
}

bool IsShuttingDown() {
    return shutting_down;
}

}  // namespace init
}  // namespace android
