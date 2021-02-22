/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "first_stage_init.h"

#include <dirent.h>
#include <fcntl.h>
#include <paths.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <filesystem>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <modprobe/modprobe.h>
#include <private/android_filesystem_config.h>

#include "debug_ramdisk.h"
#include "first_stage_console.h"
#include "first_stage_mount.h"
#include "reboot_utils.h"
#include "second_stage_resources.h"
#include "snapuserd_transition.h"
#include "switch_root.h"
#include "util.h"

using android::base::boot_clock;

using namespace std::literals;

namespace fs = std::filesystem;

namespace android {
namespace init {

namespace {

void FreeRamdisk(DIR* dir, dev_t dev) {
    int dfd = dirfd(dir);

    dirent* de;
    while ((de = readdir(dir)) != nullptr) {
        if (de->d_name == "."s || de->d_name == ".."s) {
            continue;
        }

        bool is_dir = false;

        if (de->d_type == DT_DIR || de->d_type == DT_UNKNOWN) {
            struct stat info;
            if (fstatat(dfd, de->d_name, &info, AT_SYMLINK_NOFOLLOW) != 0) {
                continue;
            }

            if (info.st_dev != dev) {
                continue;
            }

            if (S_ISDIR(info.st_mode)) {
                is_dir = true;
                auto fd = openat(dfd, de->d_name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (fd >= 0) {
                    auto subdir =
                            std::unique_ptr<DIR, decltype(&closedir)>{fdopendir(fd), closedir};
                    if (subdir) {
                        FreeRamdisk(subdir.get(), dev);
                    } else {
                        close(fd);
                    }
                }
            }
        } else if (de->d_type == DT_REG) {
            // Do not free snapuserd if we will need the ramdisk copy during the
            // selinux transition.
            if (de->d_name == "snapuserd"s && IsFirstStageSnapuserdRunning()) {
                continue;
            }
        }
        unlinkat(dfd, de->d_name, is_dir ? AT_REMOVEDIR : 0);
    }
}

bool ForceNormalBoot(const std::string& cmdline) {
    return cmdline.find("androidboot.force_normal_boot=1") != std::string::npos;
}

}  // namespace

std::string GetModuleLoadList(bool recovery, const std::string& dir_path) {
    auto module_load_file = "modules.load";
    if (recovery) {
        struct stat fileStat;
        std::string recovery_load_path = dir_path + "/modules.load.recovery";
        if (!stat(recovery_load_path.c_str(), &fileStat)) {
            module_load_file = "modules.load.recovery";
        }
    }

    return module_load_file;
}

#define MODULE_BASE_DIR "/lib/modules"
bool LoadKernelModules(bool recovery, bool want_console, int& modules_loaded) {
    struct utsname uts;
    if (uname(&uts)) {
        LOG(FATAL) << "Failed to get kernel version.";
    }
    int major, minor;
    if (sscanf(uts.release, "%d.%d", &major, &minor) != 2) {
        LOG(FATAL) << "Failed to parse kernel version " << uts.release;
    }

    std::unique_ptr<DIR, decltype(&closedir)> base_dir(opendir(MODULE_BASE_DIR), closedir);
    if (!base_dir) {
        LOG(INFO) << "Unable to open /lib/modules, skipping module loading.";
        return true;
    }
    dirent* entry;
    std::vector<std::string> module_dirs;
    while ((entry = readdir(base_dir.get()))) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        int dir_major, dir_minor;
        if (sscanf(entry->d_name, "%d.%d", &dir_major, &dir_minor) != 2 || dir_major != major ||
            dir_minor != minor) {
            continue;
        }
        module_dirs.emplace_back(entry->d_name);
    }

    // Sort the directories so they are iterated over during module loading
    // in a consistent order. Alphabetical sorting is fine here because the
    // kernel version at the beginning of the directory name must match the
    // current kernel version, so the sort only applies to a label that
    // follows the kernel version, for example /lib/modules/5.4 vs.
    // /lib/modules/5.4-gki.
    std::sort(module_dirs.begin(), module_dirs.end());

    for (const auto& module_dir : module_dirs) {
        std::string dir_path = MODULE_BASE_DIR "/";
        dir_path.append(module_dir);
        Modprobe m({dir_path}, GetModuleLoadList(recovery, dir_path));
        bool retval = m.LoadListedModules(!want_console);
        modules_loaded = m.GetModuleCount();
        if (modules_loaded > 0) {
            return retval;
        }
    }

    Modprobe m({MODULE_BASE_DIR}, GetModuleLoadList(recovery, MODULE_BASE_DIR));
    bool retval = m.LoadListedModules(!want_console);
    modules_loaded = m.GetModuleCount();
    if (modules_loaded > 0) {
        return retval;
    }
    return true;
}

int FirstStageMain(int argc, char** argv) {
    if (REBOOT_BOOTLOADER_ON_PANIC) {
        InstallRebootSignalHandlers();
    }

    boot_clock::time_point start_time = boot_clock::now();

    std::vector<std::pair<std::string, int>> errors;
#define CHECKCALL(x) \
    if ((x) != 0) errors.emplace_back(#x " failed", errno);

    // Clear the umask.
    umask(0);

    CHECKCALL(clearenv());
    CHECKCALL(setenv("PATH", _PATH_DEFPATH, 1));
    // Get the basic filesystem setup we need put together in the initramdisk
    // on / and then we'll let the rc file figure out the rest.
    CHECKCALL(mount("tmpfs", "/dev", "tmpfs", MS_NOSUID, "mode=0755"));
    CHECKCALL(mkdir("/dev/pts", 0755));
    CHECKCALL(mkdir("/dev/socket", 0755));
    CHECKCALL(mkdir("/dev/dm-user", 0755));
    CHECKCALL(mount("devpts", "/dev/pts", "devpts", 0, NULL));
#define MAKE_STR(x) __STRING(x)
    CHECKCALL(mount("proc", "/proc", "proc", 0, "hidepid=2,gid=" MAKE_STR(AID_READPROC)));
#undef MAKE_STR
    // Don't expose the raw commandline to unprivileged processes.
    CHECKCALL(chmod("/proc/cmdline", 0440));
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);
    gid_t groups[] = {AID_READPROC};
    CHECKCALL(setgroups(arraysize(groups), groups));
    CHECKCALL(mount("sysfs", "/sys", "sysfs", 0, NULL));
    CHECKCALL(mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL));

    CHECKCALL(mknod("/dev/kmsg", S_IFCHR | 0600, makedev(1, 11)));

    if constexpr (WORLD_WRITABLE_KMSG) {
        CHECKCALL(mknod("/dev/kmsg_debug", S_IFCHR | 0622, makedev(1, 11)));
    }

    CHECKCALL(mknod("/dev/random", S_IFCHR | 0666, makedev(1, 8)));
    CHECKCALL(mknod("/dev/urandom", S_IFCHR | 0666, makedev(1, 9)));

    // This is needed for log wrapper, which gets called before ueventd runs.
    CHECKCALL(mknod("/dev/ptmx", S_IFCHR | 0666, makedev(5, 2)));
    CHECKCALL(mknod("/dev/null", S_IFCHR | 0666, makedev(1, 3)));

    // These below mounts are done in first stage init so that first stage mount can mount
    // subdirectories of /mnt/{vendor,product}/.  Other mounts, not required by first stage mount,
    // should be done in rc files.
    // Mount staging areas for devices managed by vold
    // See storage config details at http://source.android.com/devices/storage/
    CHECKCALL(mount("tmpfs", "/mnt", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=1000"));
    // /mnt/vendor is used to mount vendor-specific partitions that can not be
    // part of the vendor partition, e.g. because they are mounted read-write.
    CHECKCALL(mkdir("/mnt/vendor", 0755));
    // /mnt/product is used to mount product-specific partitions that can not be
    // part of the product partition, e.g. because they are mounted read-write.
    CHECKCALL(mkdir("/mnt/product", 0755));

    // /debug_ramdisk is used to preserve additional files from the debug ramdisk
    CHECKCALL(mount("tmpfs", "/debug_ramdisk", "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=0"));

    // /second_stage_resources is used to preserve files from first to second
    // stage init
    CHECKCALL(mount("tmpfs", kSecondStageRes, "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV,
                    "mode=0755,uid=0,gid=0"))
#undef CHECKCALL

    SetStdioToDevNull(argv);
    // Now that tmpfs is mounted on /dev and we have /dev/kmsg, we can actually
    // talk to the outside world...
    InitKernelLogging(argv);

    if (!errors.empty()) {
        for (const auto& [error_string, error_errno] : errors) {
            LOG(ERROR) << error_string << " " << strerror(error_errno);
        }
        LOG(FATAL) << "Init encountered errors starting first stage, aborting";
    }

    LOG(INFO) << "init first stage started!";

    auto old_root_dir = std::unique_ptr<DIR, decltype(&closedir)>{opendir("/"), closedir};
    if (!old_root_dir) {
        PLOG(ERROR) << "Could not opendir(\"/\"), not freeing ramdisk";
    }

    struct stat old_root_info;
    if (stat("/", &old_root_info) != 0) {
        PLOG(ERROR) << "Could not stat(\"/\"), not freeing ramdisk";
        old_root_dir.reset();
    }

    auto want_console = ALLOW_FIRST_STAGE_CONSOLE ? FirstStageConsole(cmdline) : 0;

    boot_clock::time_point module_start_time = boot_clock::now();
    int module_count = 0;
    if (!LoadKernelModules(IsRecoveryMode() && !ForceNormalBoot(cmdline), want_console,
                           module_count)) {
        if (want_console != FirstStageConsoleParam::DISABLED) {
            LOG(ERROR) << "Failed to load kernel modules, starting console";
        } else {
            LOG(FATAL) << "Failed to load kernel modules";
        }
    }
    if (module_count > 0) {
        auto module_elapse_time = std::chrono::duration_cast<std::chrono::milliseconds>(
                boot_clock::now() - module_start_time);
        setenv(kEnvInitModuleDurationMs, std::to_string(module_elapse_time.count()).c_str(), 1);
        LOG(INFO) << "Loaded " << module_count << " kernel modules took "
                  << module_elapse_time.count() << " ms";
    }

    if (want_console == FirstStageConsoleParam::CONSOLE_ON_FAILURE) {
        StartConsole(cmdline);
    }

    if (access(kBootImageRamdiskProp, F_OK) == 0) {
        std::string dest = GetRamdiskPropForSecondStage();
        std::string dir = android::base::Dirname(dest);
        std::error_code ec;
        if (!fs::create_directories(dir, ec) && !!ec) {
            LOG(FATAL) << "Can't mkdir " << dir << ": " << ec.message();
        }
        if (!fs::copy_file(kBootImageRamdiskProp, dest, ec)) {
            LOG(FATAL) << "Can't copy " << kBootImageRamdiskProp << " to " << dest << ": "
                       << ec.message();
        }
        LOG(INFO) << "Copied ramdisk prop to " << dest;
    }

    if (ForceNormalBoot(cmdline)) {
        mkdir("/first_stage_ramdisk", 0755);
        // SwitchRoot() must be called with a mount point as the target, so we bind mount the
        // target directory to itself here.
        if (mount("/first_stage_ramdisk", "/first_stage_ramdisk", nullptr, MS_BIND, nullptr) != 0) {
            LOG(FATAL) << "Could not bind mount /first_stage_ramdisk to itself";
        }
        SwitchRoot("/first_stage_ramdisk");
    }

    // If this file is present, the second-stage init will use a userdebug sepolicy
    // and load adb_debug.prop to allow adb root, if the device is unlocked.
    if (access("/force_debuggable", F_OK) == 0) {
        std::error_code ec;  // to invoke the overloaded copy_file() that won't throw.
        if (!fs::copy_file("/adb_debug.prop", kDebugRamdiskProp, ec) ||
            !fs::copy_file("/userdebug_plat_sepolicy.cil", kDebugRamdiskSEPolicy, ec)) {
            LOG(ERROR) << "Failed to setup debug ramdisk";
        } else {
            // setenv for second-stage init to read above kDebugRamdisk* files.
            setenv("INIT_FORCE_DEBUGGABLE", "true", 1);
        }
    }

    if (!DoFirstStageMount()) {
        LOG(FATAL) << "Failed to mount required partitions early ...";
    }

    struct stat new_root_info;
    if (stat("/", &new_root_info) != 0) {
        PLOG(ERROR) << "Could not stat(\"/\"), not freeing ramdisk";
        old_root_dir.reset();
    }

    if (old_root_dir && old_root_info.st_dev != new_root_info.st_dev) {
        FreeRamdisk(old_root_dir.get(), old_root_info.st_dev);
    }

    SetInitAvbVersionInRecovery();

    setenv(kEnvFirstStageStartedAt, std::to_string(start_time.time_since_epoch().count()).c_str(),
           1);

    const char* path = "/system/bin/init";
    const char* args[] = {path, "selinux_setup", nullptr};
    auto fd = open("/dev/kmsg", O_WRONLY | O_CLOEXEC);
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    close(fd);
    execv(path, const_cast<char**>(args));

    // execv() only returns if an error happened, in which case we
    // panic and never fall through this conditional.
    PLOG(FATAL) << "execv(\"" << path << "\") failed";

    return 1;
}

}  // namespace init
}  // namespace android
