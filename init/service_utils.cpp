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

#include "service_utils.h"

#include <grp.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/wait.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <processgroup/processgroup.h>

#include "mount_namespace.h"

using android::base::GetProperty;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;

namespace android {
namespace init {

namespace {

Result<void> EnterNamespace(int nstype, const char* path) {
    auto fd = unique_fd{open(path, O_RDONLY | O_CLOEXEC)};
    if (fd == -1) {
        return ErrnoError() << "Could not open namespace at " << path;
    }
    if (setns(fd, nstype) == -1) {
        return ErrnoError() << "Could not setns() namespace at " << path;
    }
    return {};
}

Result<void> SetUpMountNamespace(bool remount_proc, bool remount_sys) {
    constexpr unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;

    // Recursively remount / as slave like zygote does so unmounting and mounting /proc
    // doesn't interfere with the parent namespace's /proc mount. This will also
    // prevent any other mounts/unmounts initiated by the service from interfering
    // with the parent namespace but will still allow mount events from the parent
    // namespace to propagate to the child.
    if (mount("rootfs", "/", nullptr, (MS_SLAVE | MS_REC), nullptr) == -1) {
        return ErrnoError() << "Could not remount(/) recursively as slave";
    }

    // umount() then mount() /proc and/or /sys
    // Note that it is not sufficient to mount with MS_REMOUNT.
    if (remount_proc) {
        if (umount("/proc") == -1) {
            return ErrnoError() << "Could not umount(/proc)";
        }
        if (mount("", "/proc", "proc", kSafeFlags, "") == -1) {
            return ErrnoError() << "Could not mount(/proc)";
        }
    }
    if (remount_sys) {
        if (umount2("/sys", MNT_DETACH) == -1) {
            return ErrnoError() << "Could not umount(/sys)";
        }
        if (mount("", "/sys", "sysfs", kSafeFlags, "") == -1) {
            return ErrnoError() << "Could not mount(/sys)";
        }
    }
    return {};
}

Result<void> SetUpPidNamespace(const char* name) {
    if (prctl(PR_SET_NAME, name) == -1) {
        return ErrnoError() << "Could not set name";
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        return ErrnoError() << "Could not fork init inside the PID namespace";
    }

    if (child_pid > 0) {
        // So that we exit with the right status.
        static int init_exitstatus = 0;
        signal(SIGTERM, [](int) { _exit(init_exitstatus); });

        pid_t waited_pid;
        int status;
        while ((waited_pid = wait(&status)) > 0) {
            // This loop will end when there are no processes left inside the
            // PID namespace or when the init process inside the PID namespace
            // gets a signal.
            if (waited_pid == child_pid) {
                init_exitstatus = status;
            }
        }
        if (!WIFEXITED(init_exitstatus)) {
            _exit(EXIT_FAILURE);
        }
        _exit(WEXITSTATUS(init_exitstatus));
    }
    return {};
}

void ZapStdio() {
    auto fd = unique_fd{open("/dev/null", O_RDWR | O_CLOEXEC)};
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
}

void OpenConsole(const std::string& console) {
    auto fd = unique_fd{open(console.c_str(), O_RDWR | O_CLOEXEC)};
    if (fd == -1) fd.reset(open("/dev/null", O_RDWR | O_CLOEXEC));
    ioctl(fd, TIOCSCTTY, 0);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
}

}  // namespace

Result<void> EnterNamespaces(const NamespaceInfo& info, const std::string& name, bool pre_apexd) {
    for (const auto& [nstype, path] : info.namespaces_to_enter) {
        if (auto result = EnterNamespace(nstype, path.c_str()); !result) {
            return result;
        }
    }

#if defined(__ANDROID__)
    if (pre_apexd) {
        if (!SwitchToBootstrapMountNamespaceIfNeeded()) {
            return Error() << "could not enter into the bootstrap mount namespace";
        }
    }
#endif

    if (info.flags & CLONE_NEWNS) {
        bool remount_proc = info.flags & CLONE_NEWPID;
        bool remount_sys =
                std::any_of(info.namespaces_to_enter.begin(), info.namespaces_to_enter.end(),
                            [](const auto& entry) { return entry.first == CLONE_NEWNET; });
        if (auto result = SetUpMountNamespace(remount_proc, remount_sys); !result) {
            return result;
        }
    }

    if (info.flags & CLONE_NEWPID) {
        // This will fork again to run an init process inside the PID namespace.
        if (auto result = SetUpPidNamespace(name.c_str()); !result) {
            return result;
        }
    }

    return {};
}

Result<void> SetProcessAttributes(const ProcessAttributes& attr) {
    if (attr.ioprio_class != IoSchedClass_NONE) {
        if (android_set_ioprio(getpid(), attr.ioprio_class, attr.ioprio_pri)) {
            PLOG(ERROR) << "failed to set pid " << getpid() << " ioprio=" << attr.ioprio_class
                        << "," << attr.ioprio_pri;
        }
    }

    if (!attr.console.empty()) {
        setsid();
        OpenConsole(attr.console);
    } else {
        if (setpgid(0, getpid()) == -1) {
            return ErrnoError() << "setpgid failed";
        }
        ZapStdio();
    }

    for (const auto& rlimit : attr.rlimits) {
        if (setrlimit(rlimit.first, &rlimit.second) == -1) {
            return ErrnoError() << StringPrintf(
                           "setrlimit(%d, {rlim_cur=%ld, rlim_max=%ld}) failed", rlimit.first,
                           rlimit.second.rlim_cur, rlimit.second.rlim_max);
        }
    }

    if (attr.gid) {
        if (setgid(attr.gid) != 0) {
            return ErrnoError() << "setgid failed";
        }
    }
    if (setgroups(attr.supp_gids.size(), const_cast<gid_t*>(&attr.supp_gids[0])) != 0) {
        return ErrnoError() << "setgroups failed";
    }
    if (attr.uid) {
        if (setuid(attr.uid) != 0) {
            return ErrnoError() << "setuid failed";
        }
    }

    if (attr.priority != 0) {
        if (setpriority(PRIO_PROCESS, 0, attr.priority) != 0) {
            return ErrnoError() << "setpriority failed";
        }
    }
    return {};
}

Result<void> WritePidToFiles(std::vector<std::string>* files) {
    // See if there were "writepid" instructions to write to files under cpuset path.
    std::string cpuset_path;
    if (CgroupGetControllerPath("cpuset", &cpuset_path)) {
        auto cpuset_predicate = [&cpuset_path](const std::string& path) {
            return StartsWith(path, cpuset_path + "/");
        };
        auto iter = std::find_if(files->begin(), files->end(), cpuset_predicate);
        if (iter == files->end()) {
            // There were no "writepid" instructions for cpusets, check if the system default
            // cpuset is specified to be used for the process.
            std::string default_cpuset = GetProperty("ro.cpuset.default", "");
            if (!default_cpuset.empty()) {
                // Make sure the cpuset name starts and ends with '/'.
                // A single '/' means the 'root' cpuset.
                if (default_cpuset.front() != '/') {
                    default_cpuset.insert(0, 1, '/');
                }
                if (default_cpuset.back() != '/') {
                    default_cpuset.push_back('/');
                }
                files->push_back(
                        StringPrintf("%s%stasks", cpuset_path.c_str(), default_cpuset.c_str()));
            }
        }
    } else {
        LOG(ERROR) << "cpuset cgroup controller is not mounted!";
    }
    std::string pid_str = std::to_string(getpid());
    for (const auto& file : *files) {
        if (!WriteStringToFile(pid_str, file)) {
            return ErrnoError() << "couldn't write " << pid_str << " to " << file;
        }
    }
    return {};
}

}  // namespace init
}  // namespace android
