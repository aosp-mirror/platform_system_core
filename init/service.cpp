/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "service.h"

#include <fcntl.h>
#include <inttypes.h>
#include <linux/input.h>
#include <linux/securebits.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <hidl-util/FQName.h>
#include <processgroup/processgroup.h>
#include <selinux/selinux.h>
#include <system/thread_defs.h>

#include "rlimit_parser.h"
#include "util.h"

#if defined(__ANDROID__)
#include <android/api-level.h>
#include <sys/system_properties.h>

#include "init.h"
#include "mount_namespace.h"
#include "property_service.h"
#include "selinux.h"
#else
#include "host_init_stubs.h"
#endif

using android::base::boot_clock;
using android::base::GetProperty;
using android::base::Join;
using android::base::ParseInt;
using android::base::Split;
using android::base::StartsWith;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;

namespace android {
namespace init {

static Result<std::string> ComputeContextFromExecutable(const std::string& service_path) {
    std::string computed_context;

    char* raw_con = nullptr;
    char* raw_filecon = nullptr;

    if (getcon(&raw_con) == -1) {
        return Error() << "Could not get security context";
    }
    std::unique_ptr<char> mycon(raw_con);

    if (getfilecon(service_path.c_str(), &raw_filecon) == -1) {
        return Error() << "Could not get file context";
    }
    std::unique_ptr<char> filecon(raw_filecon);

    char* new_con = nullptr;
    int rc = security_compute_create(mycon.get(), filecon.get(),
                                     string_to_security_class("process"), &new_con);
    if (rc == 0) {
        computed_context = new_con;
        free(new_con);
    }
    if (rc == 0 && computed_context == mycon.get()) {
        return Error() << "File " << service_path << "(labeled \"" << filecon.get()
                       << "\") has incorrect label or no domain transition from " << mycon.get()
                       << " to another SELinux domain defined. Have you configured your "
                          "service correctly? https://source.android.com/security/selinux/"
                          "device-policy#label_new_services_and_address_denials";
    }
    if (rc < 0) {
        return Error() << "Could not get process context";
    }
    return computed_context;
}

Result<Success> Service::SetUpMountNamespace() const {
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
    if (namespace_flags_ & CLONE_NEWPID) {
        if (umount("/proc") == -1) {
            return ErrnoError() << "Could not umount(/proc)";
        }
        if (mount("", "/proc", "proc", kSafeFlags, "") == -1) {
            return ErrnoError() << "Could not mount(/proc)";
        }
    }
    bool remount_sys = std::any_of(namespaces_to_enter_.begin(), namespaces_to_enter_.end(),
                                   [](const auto& entry) { return entry.first == CLONE_NEWNET; });
    if (remount_sys) {
        if (umount2("/sys", MNT_DETACH) == -1) {
            return ErrnoError() << "Could not umount(/sys)";
        }
        if (mount("", "/sys", "sysfs", kSafeFlags, "") == -1) {
            return ErrnoError() << "Could not mount(/sys)";
        }
    }
    return Success();
}

Result<Success> Service::SetUpPidNamespace() const {
    if (prctl(PR_SET_NAME, name_.c_str()) == -1) {
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
    return Success();
}

Result<Success> Service::EnterNamespaces() const {
    for (const auto& [nstype, path] : namespaces_to_enter_) {
        auto fd = unique_fd{open(path.c_str(), O_RDONLY | O_CLOEXEC)};
        if (fd == -1) {
            return ErrnoError() << "Could not open namespace at " << path;
        }
        if (setns(fd, nstype) == -1) {
            return ErrnoError() << "Could not setns() namespace at " << path;
        }
    }
    return Success();
}

static bool ExpandArgsAndExecv(const std::vector<std::string>& args, bool sigstop) {
    std::vector<std::string> expanded_args;
    std::vector<char*> c_strings;

    expanded_args.resize(args.size());
    c_strings.push_back(const_cast<char*>(args[0].data()));
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (!expand_props(args[i], &expanded_args[i])) {
            LOG(FATAL) << args[0] << ": cannot expand '" << args[i] << "'";
        }
        c_strings.push_back(expanded_args[i].data());
    }
    c_strings.push_back(nullptr);

    if (sigstop) {
        kill(getpid(), SIGSTOP);
    }

    return execv(c_strings[0], c_strings.data()) == 0;
}

static bool IsRuntimeApexReady() {
    struct stat buf;
    return stat("/apex/com.android.runtime/", &buf) == 0;
}

unsigned long Service::next_start_order_ = 1;
bool Service::is_exec_service_running_ = false;

Service::Service(const std::string& name, Subcontext* subcontext_for_restart_commands,
                 const std::vector<std::string>& args)
    : Service(name, 0, 0, 0, {}, 0, "", subcontext_for_restart_commands, args) {}

Service::Service(const std::string& name, unsigned flags, uid_t uid, gid_t gid,
                 const std::vector<gid_t>& supp_gids, unsigned namespace_flags,
                 const std::string& seclabel, Subcontext* subcontext_for_restart_commands,
                 const std::vector<std::string>& args)
    : name_(name),
      classnames_({"default"}),
      flags_(flags),
      pid_(0),
      crash_count_(0),
      uid_(uid),
      gid_(gid),
      supp_gids_(supp_gids),
      namespace_flags_(namespace_flags),
      seclabel_(seclabel),
      onrestart_(false, subcontext_for_restart_commands, "<Service '" + name + "' onrestart>", 0,
                 "onrestart", {}),
      ioprio_class_(IoSchedClass_NONE),
      ioprio_pri_(0),
      priority_(0),
      oom_score_adjust_(-1000),
      start_order_(0),
      args_(args) {}

void Service::NotifyStateChange(const std::string& new_state) const {
    if ((flags_ & SVC_TEMPORARY) != 0) {
        // Services created by 'exec' are temporary and don't have properties tracking their state.
        return;
    }

    std::string prop_name = "init.svc." + name_;
    property_set(prop_name, new_state);

    if (new_state == "running") {
        uint64_t start_ns = time_started_.time_since_epoch().count();
        std::string boottime_property = "ro.boottime." + name_;
        if (GetProperty(boottime_property, "").empty()) {
            property_set(boottime_property, std::to_string(start_ns));
        }
    }
}

void Service::KillProcessGroup(int signal) {
    // If we've already seen a successful result from killProcessGroup*(), then we have removed
    // the cgroup already and calling these functions a second time will simply result in an error.
    // This is true regardless of which signal was sent.
    // These functions handle their own logging, so no additional logging is needed.
    if (!process_cgroup_empty_) {
        LOG(INFO) << "Sending signal " << signal << " to service '" << name_ << "' (pid " << pid_
                  << ") process group...";
        int r;
        if (signal == SIGTERM) {
            r = killProcessGroupOnce(uid_, pid_, signal);
        } else {
            r = killProcessGroup(uid_, pid_, signal);
        }

        if (r == 0) process_cgroup_empty_ = true;
    }
}

void Service::SetProcessAttributes() {
    for (const auto& rlimit : rlimits_) {
        if (setrlimit(rlimit.first, &rlimit.second) == -1) {
            LOG(FATAL) << StringPrintf("setrlimit(%d, {rlim_cur=%ld, rlim_max=%ld}) failed",
                                       rlimit.first, rlimit.second.rlim_cur, rlimit.second.rlim_max);
        }
    }
    // Keep capabilites on uid change.
    if (capabilities_ && uid_) {
        // If Android is running in a container, some securebits might already
        // be locked, so don't change those.
        unsigned long securebits = prctl(PR_GET_SECUREBITS);
        if (securebits == -1UL) {
            PLOG(FATAL) << "prctl(PR_GET_SECUREBITS) failed for " << name_;
        }
        securebits |= SECBIT_KEEP_CAPS | SECBIT_KEEP_CAPS_LOCKED;
        if (prctl(PR_SET_SECUREBITS, securebits) != 0) {
            PLOG(FATAL) << "prctl(PR_SET_SECUREBITS) failed for " << name_;
        }
    }

    // TODO: work out why this fails for `console` then upgrade to FATAL.
    if (setpgid(0, getpid()) == -1) PLOG(ERROR) << "setpgid failed for " << name_;

    if (gid_) {
        if (setgid(gid_) != 0) {
            PLOG(FATAL) << "setgid failed for " << name_;
        }
    }
    if (setgroups(supp_gids_.size(), &supp_gids_[0]) != 0) {
        PLOG(FATAL) << "setgroups failed for " << name_;
    }
    if (uid_) {
        if (setuid(uid_) != 0) {
            PLOG(FATAL) << "setuid failed for " << name_;
        }
    }
    if (!seclabel_.empty()) {
        if (setexeccon(seclabel_.c_str()) < 0) {
            PLOG(FATAL) << "cannot setexeccon('" << seclabel_ << "') for " << name_;
        }
    }
    if (priority_ != 0) {
        if (setpriority(PRIO_PROCESS, 0, priority_) != 0) {
            PLOG(FATAL) << "setpriority failed for " << name_;
        }
    }
    if (capabilities_) {
        if (!SetCapsForExec(*capabilities_)) {
            LOG(FATAL) << "cannot set capabilities for " << name_;
        }
    } else if (uid_) {
        // Inheritable caps can be non-zero when running in a container.
        if (!DropInheritableCaps()) {
            LOG(FATAL) << "cannot drop inheritable caps for " << name_;
        }
    }
}

void Service::Reap(const siginfo_t& siginfo) {
    if (!(flags_ & SVC_ONESHOT) || (flags_ & SVC_RESTART)) {
        KillProcessGroup(SIGKILL);
    }

    // Remove any descriptor resources we may have created.
    std::for_each(descriptors_.begin(), descriptors_.end(),
                  std::bind(&DescriptorInfo::Clean, std::placeholders::_1));

    for (const auto& f : reap_callbacks_) {
        f(siginfo);
    }

    if (flags_ & SVC_EXEC) UnSetExec();

    if (flags_ & SVC_TEMPORARY) return;

    pid_ = 0;
    flags_ &= (~SVC_RUNNING);
    start_order_ = 0;

    // Oneshot processes go into the disabled state on exit,
    // except when manually restarted.
    if ((flags_ & SVC_ONESHOT) && !(flags_ & SVC_RESTART) && !(flags_ & SVC_RESET)) {
        flags_ |= SVC_DISABLED;
    }

    // Disabled and reset processes do not get restarted automatically.
    if (flags_ & (SVC_DISABLED | SVC_RESET))  {
        NotifyStateChange("stopped");
        return;
    }

    // If we crash > 4 times in 4 minutes or before boot_completed,
    // reboot into bootloader or set crashing property
    boot_clock::time_point now = boot_clock::now();
    if (((flags_ & SVC_CRITICAL) || !pre_apexd_) && !(flags_ & SVC_RESTART)) {
        bool boot_completed = android::base::GetBoolProperty("sys.boot_completed", false);
        if (now < time_crashed_ + 4min || !boot_completed) {
            if (++crash_count_ > 4) {
                if (flags_ & SVC_CRITICAL) {
                    // Aborts into bootloader
                    LOG(FATAL) << "critical process '" << name_ << "' exited 4 times "
                               << (boot_completed ? "in 4 minutes" : "before boot completed");
                } else {
                    LOG(ERROR) << "updatable process '" << name_ << "' exited 4 times "
                               << (boot_completed ? "in 4 minutes" : "before boot completed");
                    // Notifies update_verifier and apexd
                    property_set("ro.init.updatable_crashing_process_name", name_);
                    property_set("ro.init.updatable_crashing", "1");
                }
            }
        } else {
            time_crashed_ = now;
            crash_count_ = 1;
        }
    }

    flags_ &= (~SVC_RESTART);
    flags_ |= SVC_RESTARTING;

    // Execute all onrestart commands for this service.
    onrestart_.ExecuteAllCommands();

    NotifyStateChange("restarting");
    return;
}

void Service::DumpState() const {
    LOG(INFO) << "service " << name_;
    LOG(INFO) << "  class '" << Join(classnames_, " ") << "'";
    LOG(INFO) << "  exec " << Join(args_, " ");
    std::for_each(descriptors_.begin(), descriptors_.end(),
                  [] (const auto& info) { LOG(INFO) << *info; });
}

Result<Success> Service::ParseCapabilities(std::vector<std::string>&& args) {
    capabilities_ = 0;

    if (!CapAmbientSupported()) {
        return Error()
               << "capabilities requested but the kernel does not support ambient capabilities";
    }

    unsigned int last_valid_cap = GetLastValidCap();
    if (last_valid_cap >= capabilities_->size()) {
        LOG(WARNING) << "last valid run-time capability is larger than CAP_LAST_CAP";
    }

    for (size_t i = 1; i < args.size(); i++) {
        const std::string& arg = args[i];
        int res = LookupCap(arg);
        if (res < 0) {
            return Error() << StringPrintf("invalid capability '%s'", arg.c_str());
        }
        unsigned int cap = static_cast<unsigned int>(res);  // |res| is >= 0.
        if (cap > last_valid_cap) {
            return Error() << StringPrintf("capability '%s' not supported by the kernel",
                                           arg.c_str());
        }
        (*capabilities_)[cap] = true;
    }
    return Success();
}

Result<Success> Service::ParseClass(std::vector<std::string>&& args) {
    classnames_ = std::set<std::string>(args.begin() + 1, args.end());
    return Success();
}

Result<Success> Service::ParseConsole(std::vector<std::string>&& args) {
    flags_ |= SVC_CONSOLE;
    console_ = args.size() > 1 ? "/dev/" + args[1] : "";
    return Success();
}

Result<Success> Service::ParseCritical(std::vector<std::string>&& args) {
    flags_ |= SVC_CRITICAL;
    return Success();
}

Result<Success> Service::ParseDisabled(std::vector<std::string>&& args) {
    flags_ |= SVC_DISABLED;
    flags_ |= SVC_RC_DISABLED;
    return Success();
}

Result<Success> Service::ParseEnterNamespace(std::vector<std::string>&& args) {
    if (args[1] != "net") {
        return Error() << "Init only supports entering network namespaces";
    }
    if (!namespaces_to_enter_.empty()) {
        return Error() << "Only one network namespace may be entered";
    }
    // Network namespaces require that /sys is remounted, otherwise the old adapters will still be
    // present. Therefore, they also require mount namespaces.
    namespace_flags_ |= CLONE_NEWNS;
    namespaces_to_enter_.emplace_back(CLONE_NEWNET, std::move(args[2]));
    return Success();
}

Result<Success> Service::ParseGroup(std::vector<std::string>&& args) {
    auto gid = DecodeUid(args[1]);
    if (!gid) {
        return Error() << "Unable to decode GID for '" << args[1] << "': " << gid.error();
    }
    gid_ = *gid;

    for (std::size_t n = 2; n < args.size(); n++) {
        gid = DecodeUid(args[n]);
        if (!gid) {
            return Error() << "Unable to decode GID for '" << args[n] << "': " << gid.error();
        }
        supp_gids_.emplace_back(*gid);
    }
    return Success();
}

Result<Success> Service::ParsePriority(std::vector<std::string>&& args) {
    priority_ = 0;
    if (!ParseInt(args[1], &priority_,
                  static_cast<int>(ANDROID_PRIORITY_HIGHEST), // highest is negative
                  static_cast<int>(ANDROID_PRIORITY_LOWEST))) {
        return Error() << StringPrintf("process priority value must be range %d - %d",
                                       ANDROID_PRIORITY_HIGHEST, ANDROID_PRIORITY_LOWEST);
    }
    return Success();
}

Result<Success> Service::ParseInterface(std::vector<std::string>&& args) {
    const std::string& interface_name = args[1];
    const std::string& instance_name = args[2];

    FQName fq_name;
    if (!FQName::parse(interface_name, &fq_name)) {
        return Error() << "Invalid fully-qualified name for interface '" << interface_name << "'";
    }

    if (!fq_name.isFullyQualified()) {
        return Error() << "Interface name not fully-qualified '" << interface_name << "'";
    }

    if (fq_name.isValidValueName()) {
        return Error() << "Interface name must not be a value name '" << interface_name << "'";
    }

    const std::string fullname = interface_name + "/" + instance_name;

    for (const auto& svc : ServiceList::GetInstance()) {
        if (svc->interfaces().count(fullname) > 0) {
            return Error() << "Interface '" << fullname << "' redefined in " << name()
                           << " but is already defined by " << svc->name();
        }
    }

    interfaces_.insert(fullname);

    return Success();
}

Result<Success> Service::ParseIoprio(std::vector<std::string>&& args) {
    if (!ParseInt(args[2], &ioprio_pri_, 0, 7)) {
        return Error() << "priority value must be range 0 - 7";
    }

    if (args[1] == "rt") {
        ioprio_class_ = IoSchedClass_RT;
    } else if (args[1] == "be") {
        ioprio_class_ = IoSchedClass_BE;
    } else if (args[1] == "idle") {
        ioprio_class_ = IoSchedClass_IDLE;
    } else {
        return Error() << "ioprio option usage: ioprio <rt|be|idle> <0-7>";
    }

    return Success();
}

Result<Success> Service::ParseKeycodes(std::vector<std::string>&& args) {
    auto it = args.begin() + 1;
    if (args.size() == 2 && StartsWith(args[1], "$")) {
        std::string expanded;
        if (!expand_props(args[1], &expanded)) {
            return Error() << "Could not expand property '" << args[1] << "'";
        }

        // If the property is not set, it defaults to none, in which case there are no keycodes
        // for this service.
        if (expanded == "none") {
            return Success();
        }

        args = Split(expanded, ",");
        it = args.begin();
    }

    for (; it != args.end(); ++it) {
        int code;
        if (ParseInt(*it, &code, 0, KEY_MAX)) {
            for (auto& key : keycodes_) {
                if (key == code) return Error() << "duplicate keycode: " << *it;
            }
            keycodes_.insert(std::upper_bound(keycodes_.begin(), keycodes_.end(), code), code);
        } else {
            return Error() << "invalid keycode: " << *it;
        }
    }
    return Success();
}

Result<Success> Service::ParseOneshot(std::vector<std::string>&& args) {
    flags_ |= SVC_ONESHOT;
    return Success();
}

Result<Success> Service::ParseOnrestart(std::vector<std::string>&& args) {
    args.erase(args.begin());
    int line = onrestart_.NumCommands() + 1;
    if (auto result = onrestart_.AddCommand(std::move(args), line); !result) {
        return Error() << "cannot add Onrestart command: " << result.error();
    }
    return Success();
}

Result<Success> Service::ParseNamespace(std::vector<std::string>&& args) {
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "pid") {
            namespace_flags_ |= CLONE_NEWPID;
            // PID namespaces require mount namespaces.
            namespace_flags_ |= CLONE_NEWNS;
        } else if (args[i] == "mnt") {
            namespace_flags_ |= CLONE_NEWNS;
        } else {
            return Error() << "namespace must be 'pid' or 'mnt'";
        }
    }
    return Success();
}

Result<Success> Service::ParseOomScoreAdjust(std::vector<std::string>&& args) {
    if (!ParseInt(args[1], &oom_score_adjust_, -1000, 1000)) {
        return Error() << "oom_score_adjust value must be in range -1000 - +1000";
    }
    return Success();
}

Result<Success> Service::ParseOverride(std::vector<std::string>&& args) {
    override_ = true;
    return Success();
}

Result<Success> Service::ParseMemcgSwappiness(std::vector<std::string>&& args) {
    if (!ParseInt(args[1], &swappiness_, 0)) {
        return Error() << "swappiness value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseMemcgLimitInBytes(std::vector<std::string>&& args) {
    if (!ParseInt(args[1], &limit_in_bytes_, 0)) {
        return Error() << "limit_in_bytes value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseMemcgLimitPercent(std::vector<std::string>&& args) {
    if (!ParseInt(args[1], &limit_percent_, 0)) {
        return Error() << "limit_percent value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseMemcgLimitProperty(std::vector<std::string>&& args) {
    limit_property_ = std::move(args[1]);
    return Success();
}

Result<Success> Service::ParseMemcgSoftLimitInBytes(std::vector<std::string>&& args) {
    if (!ParseInt(args[1], &soft_limit_in_bytes_, 0)) {
        return Error() << "soft_limit_in_bytes value must be equal or greater than 0";
    }
    return Success();
}

Result<Success> Service::ParseProcessRlimit(std::vector<std::string>&& args) {
    auto rlimit = ParseRlimit(args);
    if (!rlimit) return rlimit.error();

    rlimits_.emplace_back(*rlimit);
    return Success();
}

Result<Success> Service::ParseRestartPeriod(std::vector<std::string>&& args) {
    int period;
    if (!ParseInt(args[1], &period, 5)) {
        return Error() << "restart_period value must be an integer >= 5";
    }
    restart_period_ = std::chrono::seconds(period);
    return Success();
}

Result<Success> Service::ParseSeclabel(std::vector<std::string>&& args) {
    seclabel_ = std::move(args[1]);
    return Success();
}

Result<Success> Service::ParseSigstop(std::vector<std::string>&& args) {
    sigstop_ = true;
    return Success();
}

Result<Success> Service::ParseSetenv(std::vector<std::string>&& args) {
    environment_vars_.emplace_back(std::move(args[1]), std::move(args[2]));
    return Success();
}

Result<Success> Service::ParseShutdown(std::vector<std::string>&& args) {
    if (args[1] == "critical") {
        flags_ |= SVC_SHUTDOWN_CRITICAL;
        return Success();
    }
    return Error() << "Invalid shutdown option";
}

Result<Success> Service::ParseTimeoutPeriod(std::vector<std::string>&& args) {
    int period;
    if (!ParseInt(args[1], &period, 1)) {
        return Error() << "timeout_period value must be an integer >= 1";
    }
    timeout_period_ = std::chrono::seconds(period);
    return Success();
}

template <typename T>
Result<Success> Service::AddDescriptor(std::vector<std::string>&& args) {
    int perm = args.size() > 3 ? std::strtoul(args[3].c_str(), 0, 8) : -1;
    Result<uid_t> uid = 0;
    Result<gid_t> gid = 0;
    std::string context = args.size() > 6 ? args[6] : "";

    if (args.size() > 4) {
        uid = DecodeUid(args[4]);
        if (!uid) {
            return Error() << "Unable to find UID for '" << args[4] << "': " << uid.error();
        }
    }

    if (args.size() > 5) {
        gid = DecodeUid(args[5]);
        if (!gid) {
            return Error() << "Unable to find GID for '" << args[5] << "': " << gid.error();
        }
    }

    auto descriptor = std::make_unique<T>(args[1], args[2], *uid, *gid, perm, context);

    auto old =
        std::find_if(descriptors_.begin(), descriptors_.end(),
                     [&descriptor] (const auto& other) { return descriptor.get() == other.get(); });

    if (old != descriptors_.end()) {
        return Error() << "duplicate descriptor " << args[1] << " " << args[2];
    }

    descriptors_.emplace_back(std::move(descriptor));
    return Success();
}

// name type perm [ uid gid context ]
Result<Success> Service::ParseSocket(std::vector<std::string>&& args) {
    if (!StartsWith(args[2], "dgram") && !StartsWith(args[2], "stream") &&
        !StartsWith(args[2], "seqpacket")) {
        return Error() << "socket type must be 'dgram', 'stream' or 'seqpacket'";
    }
    return AddDescriptor<SocketInfo>(std::move(args));
}

// name type perm [ uid gid context ]
Result<Success> Service::ParseFile(std::vector<std::string>&& args) {
    if (args[2] != "r" && args[2] != "w" && args[2] != "rw") {
        return Error() << "file type must be 'r', 'w' or 'rw'";
    }
    std::string expanded;
    if (!expand_props(args[1], &expanded)) {
        return Error() << "Could not expand property in file path '" << args[1] << "'";
    }
    args[1] = std::move(expanded);
    if ((args[1][0] != '/') || (args[1].find("../") != std::string::npos)) {
        return Error() << "file name must not be relative";
    }
    return AddDescriptor<FileInfo>(std::move(args));
}

Result<Success> Service::ParseUser(std::vector<std::string>&& args) {
    auto uid = DecodeUid(args[1]);
    if (!uid) {
        return Error() << "Unable to find UID for '" << args[1] << "': " << uid.error();
    }
    uid_ = *uid;
    return Success();
}

Result<Success> Service::ParseWritepid(std::vector<std::string>&& args) {
    args.erase(args.begin());
    writepid_files_ = std::move(args);
    return Success();
}

Result<Success> Service::ParseUpdatable(std::vector<std::string>&& args) {
    updatable_ = true;
    return Success();
}

class Service::OptionParserMap : public KeywordMap<OptionParser> {
  public:
    OptionParserMap() {}

  private:
    const Map& map() const override;
};

const Service::OptionParserMap::Map& Service::OptionParserMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    // clang-format off
    static const Map option_parsers = {
        {"capabilities",
                        {0,     kMax, &Service::ParseCapabilities}},
        {"class",       {1,     kMax, &Service::ParseClass}},
        {"console",     {0,     1,    &Service::ParseConsole}},
        {"critical",    {0,     0,    &Service::ParseCritical}},
        {"disabled",    {0,     0,    &Service::ParseDisabled}},
        {"enter_namespace",
                        {2,     2,    &Service::ParseEnterNamespace}},
        {"file",        {2,     2,    &Service::ParseFile}},
        {"group",       {1,     NR_SVC_SUPP_GIDS + 1, &Service::ParseGroup}},
        {"interface",   {2,     2,    &Service::ParseInterface}},
        {"ioprio",      {2,     2,    &Service::ParseIoprio}},
        {"keycodes",    {1,     kMax, &Service::ParseKeycodes}},
        {"memcg.limit_in_bytes",
                        {1,     1,    &Service::ParseMemcgLimitInBytes}},
        {"memcg.limit_percent",
                        {1,     1,    &Service::ParseMemcgLimitPercent}},
        {"memcg.limit_property",
                        {1,     1,    &Service::ParseMemcgLimitProperty}},
        {"memcg.soft_limit_in_bytes",
                        {1,     1,    &Service::ParseMemcgSoftLimitInBytes}},
        {"memcg.swappiness",
                        {1,     1,    &Service::ParseMemcgSwappiness}},
        {"namespace",   {1,     2,    &Service::ParseNamespace}},
        {"oneshot",     {0,     0,    &Service::ParseOneshot}},
        {"onrestart",   {1,     kMax, &Service::ParseOnrestart}},
        {"oom_score_adjust",
                        {1,     1,    &Service::ParseOomScoreAdjust}},
        {"override",    {0,     0,    &Service::ParseOverride}},
        {"priority",    {1,     1,    &Service::ParsePriority}},
        {"restart_period",
                        {1,     1,    &Service::ParseRestartPeriod}},
        {"rlimit",      {3,     3,    &Service::ParseProcessRlimit}},
        {"seclabel",    {1,     1,    &Service::ParseSeclabel}},
        {"setenv",      {2,     2,    &Service::ParseSetenv}},
        {"shutdown",    {1,     1,    &Service::ParseShutdown}},
        {"sigstop",     {0,     0,    &Service::ParseSigstop}},
        {"socket",      {3,     6,    &Service::ParseSocket}},
        {"timeout_period",
                        {1,     1,    &Service::ParseTimeoutPeriod}},
        {"updatable",   {0,     0,    &Service::ParseUpdatable}},
        {"user",        {1,     1,    &Service::ParseUser}},
        {"writepid",    {1,     kMax, &Service::ParseWritepid}},
    };
    // clang-format on
    return option_parsers;
}

Result<Success> Service::ParseLine(std::vector<std::string>&& args) {
    static const OptionParserMap parser_map;
    auto parser = parser_map.FindFunction(args);

    if (!parser) return parser.error();

    return std::invoke(*parser, this, std::move(args));
}

Result<Success> Service::ExecStart() {
    if (is_updatable() && !ServiceList::GetInstance().IsServicesUpdated()) {
        // Don't delay the service for ExecStart() as the semantic is that
        // the caller might depend on the side effect of the execution.
        return Error() << "Cannot start an updatable service '" << name_
                       << "' before configs from APEXes are all loaded";
    }

    flags_ |= SVC_ONESHOT;

    if (auto result = Start(); !result) {
        return result;
    }

    flags_ |= SVC_EXEC;
    is_exec_service_running_ = true;

    LOG(INFO) << "SVC_EXEC service '" << name_ << "' pid " << pid_ << " (uid " << uid_ << " gid "
              << gid_ << "+" << supp_gids_.size() << " context "
              << (!seclabel_.empty() ? seclabel_ : "default") << ") started; waiting...";

    return Success();
}

Result<Success> Service::Start() {
    if (is_updatable() && !ServiceList::GetInstance().IsServicesUpdated()) {
        ServiceList::GetInstance().DelayService(*this);
        return Error() << "Cannot start an updatable service '" << name_
                       << "' before configs from APEXes are all loaded. "
                       << "Queued for execution.";
    }

    bool disabled = (flags_ & (SVC_DISABLED | SVC_RESET));
    // Starting a service removes it from the disabled or reset state and
    // immediately takes it out of the restarting state if it was in there.
    flags_ &= (~(SVC_DISABLED|SVC_RESTARTING|SVC_RESET|SVC_RESTART|SVC_DISABLED_START));

    // Running processes require no additional work --- if they're in the
    // process of exiting, we've ensured that they will immediately restart
    // on exit, unless they are ONESHOT. For ONESHOT service, if it's in
    // stopping status, we just set SVC_RESTART flag so it will get restarted
    // in Reap().
    if (flags_ & SVC_RUNNING) {
        if ((flags_ & SVC_ONESHOT) && disabled) {
            flags_ |= SVC_RESTART;
        }
        // It is not an error to try to start a service that is already running.
        return Success();
    }

    bool needs_console = (flags_ & SVC_CONSOLE);
    if (needs_console) {
        if (console_.empty()) {
            console_ = default_console;
        }

        // Make sure that open call succeeds to ensure a console driver is
        // properly registered for the device node
        int console_fd = open(console_.c_str(), O_RDWR | O_CLOEXEC);
        if (console_fd < 0) {
            flags_ |= SVC_DISABLED;
            return ErrnoError() << "Couldn't open console '" << console_ << "'";
        }
        close(console_fd);
    }

    struct stat sb;
    if (stat(args_[0].c_str(), &sb) == -1) {
        flags_ |= SVC_DISABLED;
        return ErrnoError() << "Cannot find '" << args_[0] << "'";
    }

    std::string scon;
    if (!seclabel_.empty()) {
        scon = seclabel_;
    } else {
        auto result = ComputeContextFromExecutable(args_[0]);
        if (!result) {
            return result.error();
        }
        scon = *result;
    }

    if (!IsRuntimeApexReady() && !pre_apexd_) {
        // If this service is started before the runtime APEX gets available,
        // mark it as pre-apexd one. Note that this marking is permanent. So
        // for example, if the service is re-launched (e.g., due to crash),
        // it is still recognized as pre-apexd... for consistency.
        pre_apexd_ = true;
    }

    post_data_ = ServiceList::GetInstance().IsPostData();

    LOG(INFO) << "starting service '" << name_ << "'...";

    pid_t pid = -1;
    if (namespace_flags_) {
        pid = clone(nullptr, nullptr, namespace_flags_ | SIGCHLD, nullptr);
    } else {
        pid = fork();
    }

    if (pid == 0) {
        umask(077);

        if (auto result = EnterNamespaces(); !result) {
            LOG(FATAL) << "Service '" << name_ << "' could not enter namespaces: " << result.error();
        }

#if defined(__ANDROID__)
        if (pre_apexd_) {
            if (!SwitchToBootstrapMountNamespaceIfNeeded()) {
                LOG(FATAL) << "Service '" << name_ << "' could not enter "
                           << "into the bootstrap mount namespace";
            }
        }
#endif

        if (namespace_flags_ & CLONE_NEWNS) {
            if (auto result = SetUpMountNamespace(); !result) {
                LOG(FATAL) << "Service '" << name_
                           << "' could not set up mount namespace: " << result.error();
            }
        }

        if (namespace_flags_ & CLONE_NEWPID) {
            // This will fork again to run an init process inside the PID
            // namespace.
            if (auto result = SetUpPidNamespace(); !result) {
                LOG(FATAL) << "Service '" << name_
                           << "' could not set up PID namespace: " << result.error();
            }
        }

        for (const auto& [key, value] : environment_vars_) {
            setenv(key.c_str(), value.c_str(), 1);
        }

        std::for_each(descriptors_.begin(), descriptors_.end(),
                      std::bind(&DescriptorInfo::CreateAndPublish, std::placeholders::_1, scon));

        // See if there were "writepid" instructions to write to files under cpuset path.
        std::string cpuset_path;
        if (CgroupGetControllerPath("cpuset", &cpuset_path)) {
            auto cpuset_predicate = [&cpuset_path](const std::string& path) {
                return StartsWith(path, cpuset_path + "/");
            };
            auto iter =
                    std::find_if(writepid_files_.begin(), writepid_files_.end(), cpuset_predicate);
            if (iter == writepid_files_.end()) {
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
                    writepid_files_.push_back(
                            StringPrintf("%s%stasks", cpuset_path.c_str(), default_cpuset.c_str()));
                }
            }
        } else {
            LOG(ERROR) << "cpuset cgroup controller is not mounted!";
        }
        std::string pid_str = std::to_string(getpid());
        for (const auto& file : writepid_files_) {
            if (!WriteStringToFile(pid_str, file)) {
                PLOG(ERROR) << "couldn't write " << pid_str << " to " << file;
            }
        }

        if (ioprio_class_ != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), ioprio_class_, ioprio_pri_)) {
                PLOG(ERROR) << "failed to set pid " << getpid()
                            << " ioprio=" << ioprio_class_ << "," << ioprio_pri_;
            }
        }

        if (needs_console) {
            setsid();
            OpenConsole();
        } else {
            ZapStdio();
        }

        // As requested, set our gid, supplemental gids, uid, context, and
        // priority. Aborts on failure.
        SetProcessAttributes();

        if (!ExpandArgsAndExecv(args_, sigstop_)) {
            PLOG(ERROR) << "cannot execve('" << args_[0] << "')";
        }

        _exit(127);
    }

    if (pid < 0) {
        pid_ = 0;
        return ErrnoError() << "Failed to fork";
    }

    if (oom_score_adjust_ != -1000) {
        std::string oom_str = std::to_string(oom_score_adjust_);
        std::string oom_file = StringPrintf("/proc/%d/oom_score_adj", pid);
        if (!WriteStringToFile(oom_str, oom_file)) {
            PLOG(ERROR) << "couldn't write oom_score_adj";
        }
    }

    time_started_ = boot_clock::now();
    pid_ = pid;
    flags_ |= SVC_RUNNING;
    start_order_ = next_start_order_++;
    process_cgroup_empty_ = false;

    bool use_memcg = swappiness_ != -1 || soft_limit_in_bytes_ != -1 || limit_in_bytes_ != -1 ||
                      limit_percent_ != -1 || !limit_property_.empty();
    errno = -createProcessGroup(uid_, pid_, use_memcg);
    if (errno != 0) {
        PLOG(ERROR) << "createProcessGroup(" << uid_ << ", " << pid_ << ") failed for service '"
                    << name_ << "'";
    } else if (use_memcg) {
        if (swappiness_ != -1) {
            if (!setProcessGroupSwappiness(uid_, pid_, swappiness_)) {
                PLOG(ERROR) << "setProcessGroupSwappiness failed";
            }
        }

        if (soft_limit_in_bytes_ != -1) {
            if (!setProcessGroupSoftLimit(uid_, pid_, soft_limit_in_bytes_)) {
                PLOG(ERROR) << "setProcessGroupSoftLimit failed";
            }
        }

        size_t computed_limit_in_bytes = limit_in_bytes_;
        if (limit_percent_ != -1) {
            long page_size = sysconf(_SC_PAGESIZE);
            long num_pages = sysconf(_SC_PHYS_PAGES);
            if (page_size > 0 && num_pages > 0) {
                size_t max_mem = SIZE_MAX;
                if (size_t(num_pages) < SIZE_MAX / size_t(page_size)) {
                    max_mem = size_t(num_pages) * size_t(page_size);
                }
                computed_limit_in_bytes =
                        std::min(computed_limit_in_bytes, max_mem / 100 * limit_percent_);
            }
        }

        if (!limit_property_.empty()) {
            // This ends up overwriting computed_limit_in_bytes but only if the
            // property is defined.
            computed_limit_in_bytes = android::base::GetUintProperty(
                    limit_property_, computed_limit_in_bytes, SIZE_MAX);
        }

        if (computed_limit_in_bytes != size_t(-1)) {
            if (!setProcessGroupLimit(uid_, pid_, computed_limit_in_bytes)) {
                PLOG(ERROR) << "setProcessGroupLimit failed";
            }
        }
    }

    NotifyStateChange("running");
    return Success();
}

Result<Success> Service::StartIfNotDisabled() {
    if (!(flags_ & SVC_DISABLED)) {
        return Start();
    } else {
        flags_ |= SVC_DISABLED_START;
    }
    return Success();
}

Result<Success> Service::Enable() {
    flags_ &= ~(SVC_DISABLED | SVC_RC_DISABLED);
    if (flags_ & SVC_DISABLED_START) {
        return Start();
    }
    return Success();
}

void Service::Reset() {
    StopOrReset(SVC_RESET);
}

void Service::ResetIfPostData() {
    if (post_data_) {
        if (flags_ & SVC_RUNNING) {
            running_at_post_data_reset_ = true;
        }
        StopOrReset(SVC_RESET);
    }
}

Result<Success> Service::StartIfPostData() {
    // Start the service, but only if it was started after /data was mounted,
    // and it was still running when we reset the post-data services.
    if (running_at_post_data_reset_) {
        return Start();
    }

    return Success();
}

void Service::Stop() {
    StopOrReset(SVC_DISABLED);
}

void Service::Terminate() {
    flags_ &= ~(SVC_RESTARTING | SVC_DISABLED_START);
    flags_ |= SVC_DISABLED;
    if (pid_) {
        KillProcessGroup(SIGTERM);
        NotifyStateChange("stopping");
    }
}

void Service::Timeout() {
    // All process state flags will be taken care of in Reap(), we really just want to kill the
    // process here when it times out.  Oneshot processes will transition to be disabled, and
    // all other processes will transition to be restarting.
    LOG(INFO) << "Service '" << name_ << "' expired its timeout of " << timeout_period_->count()
              << " seconds and will now be killed";
    if (pid_) {
        KillProcessGroup(SIGKILL);
        NotifyStateChange("stopping");
    }
}

void Service::Restart() {
    if (flags_ & SVC_RUNNING) {
        /* Stop, wait, then start the service. */
        StopOrReset(SVC_RESTART);
    } else if (!(flags_ & SVC_RESTARTING)) {
        /* Just start the service since it's not running. */
        if (auto result = Start(); !result) {
            LOG(ERROR) << "Could not restart '" << name_ << "': " << result.error();
        }
    } /* else: Service is restarting anyways. */
}

// The how field should be either SVC_DISABLED, SVC_RESET, or SVC_RESTART.
void Service::StopOrReset(int how) {
    // The service is still SVC_RUNNING until its process exits, but if it has
    // already exited it shoudn't attempt a restart yet.
    flags_ &= ~(SVC_RESTARTING | SVC_DISABLED_START);

    if ((how != SVC_DISABLED) && (how != SVC_RESET) && (how != SVC_RESTART)) {
        // An illegal flag: default to SVC_DISABLED.
        how = SVC_DISABLED;
    }

    // If the service has not yet started, prevent it from auto-starting with its class.
    if (how == SVC_RESET) {
        flags_ |= (flags_ & SVC_RC_DISABLED) ? SVC_DISABLED : SVC_RESET;
    } else {
        flags_ |= how;
    }
    // Make sure it's in right status when a restart immediately follow a
    // stop/reset or vice versa.
    if (how == SVC_RESTART) {
        flags_ &= (~(SVC_DISABLED | SVC_RESET));
    } else {
        flags_ &= (~SVC_RESTART);
    }

    if (pid_) {
        KillProcessGroup(SIGKILL);
        NotifyStateChange("stopping");
    } else {
        NotifyStateChange("stopped");
    }
}

void Service::ZapStdio() const {
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

void Service::OpenConsole() const {
    int fd = open(console_.c_str(), O_RDWR);
    if (fd == -1) fd = open("/dev/null", O_RDWR);
    ioctl(fd, TIOCSCTTY, 0);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

ServiceList::ServiceList() {}

ServiceList& ServiceList::GetInstance() {
    static ServiceList instance;
    return instance;
}

void ServiceList::AddService(std::unique_ptr<Service> service) {
    services_.emplace_back(std::move(service));
}

std::unique_ptr<Service> Service::MakeTemporaryOneshotService(const std::vector<std::string>& args) {
    // Parse the arguments: exec [SECLABEL [UID [GID]*] --] COMMAND ARGS...
    // SECLABEL can be a - to denote default
    std::size_t command_arg = 1;
    for (std::size_t i = 1; i < args.size(); ++i) {
        if (args[i] == "--") {
            command_arg = i + 1;
            break;
        }
    }
    if (command_arg > 4 + NR_SVC_SUPP_GIDS) {
        LOG(ERROR) << "exec called with too many supplementary group ids";
        return nullptr;
    }

    if (command_arg >= args.size()) {
        LOG(ERROR) << "exec called without command";
        return nullptr;
    }
    std::vector<std::string> str_args(args.begin() + command_arg, args.end());

    static size_t exec_count = 0;
    exec_count++;
    std::string name = "exec " + std::to_string(exec_count) + " (" + Join(str_args, " ") + ")";

    unsigned flags = SVC_ONESHOT | SVC_TEMPORARY;
    unsigned namespace_flags = 0;

    std::string seclabel = "";
    if (command_arg > 2 && args[1] != "-") {
        seclabel = args[1];
    }
    Result<uid_t> uid = 0;
    if (command_arg > 3) {
        uid = DecodeUid(args[2]);
        if (!uid) {
            LOG(ERROR) << "Unable to decode UID for '" << args[2] << "': " << uid.error();
            return nullptr;
        }
    }
    Result<gid_t> gid = 0;
    std::vector<gid_t> supp_gids;
    if (command_arg > 4) {
        gid = DecodeUid(args[3]);
        if (!gid) {
            LOG(ERROR) << "Unable to decode GID for '" << args[3] << "': " << gid.error();
            return nullptr;
        }
        std::size_t nr_supp_gids = command_arg - 1 /* -- */ - 4 /* exec SECLABEL UID GID */;
        for (size_t i = 0; i < nr_supp_gids; ++i) {
            auto supp_gid = DecodeUid(args[4 + i]);
            if (!supp_gid) {
                LOG(ERROR) << "Unable to decode GID for '" << args[4 + i]
                           << "': " << supp_gid.error();
                return nullptr;
            }
            supp_gids.push_back(*supp_gid);
        }
    }

    return std::make_unique<Service>(name, flags, *uid, *gid, supp_gids, namespace_flags, seclabel,
                                     nullptr, str_args);
}

// Shutdown services in the opposite order that they were started.
const std::vector<Service*> ServiceList::services_in_shutdown_order() const {
    std::vector<Service*> shutdown_services;
    for (const auto& service : services_) {
        if (service->start_order() > 0) shutdown_services.emplace_back(service.get());
    }
    std::sort(shutdown_services.begin(), shutdown_services.end(),
              [](const auto& a, const auto& b) { return a->start_order() > b->start_order(); });
    return shutdown_services;
}

void ServiceList::RemoveService(const Service& svc) {
    auto svc_it = std::find_if(services_.begin(), services_.end(),
                               [&svc] (const std::unique_ptr<Service>& s) {
                                   return svc.name() == s->name();
                               });
    if (svc_it == services_.end()) {
        return;
    }

    services_.erase(svc_it);
}

void ServiceList::DumpState() const {
    for (const auto& s : services_) {
        s->DumpState();
    }
}

void ServiceList::MarkPostData() {
    post_data_ = true;
}

bool ServiceList::IsPostData() {
    return post_data_;
}

void ServiceList::MarkServicesUpdate() {
    services_update_finished_ = true;

    // start the delayed services
    for (const auto& name : delayed_service_names_) {
        Service* service = FindService(name);
        if (service == nullptr) {
            LOG(ERROR) << "delayed service '" << name << "' could not be found.";
            continue;
        }
        if (auto result = service->Start(); !result) {
            LOG(ERROR) << result.error_string();
        }
    }
    delayed_service_names_.clear();
}

void ServiceList::DelayService(const Service& service) {
    if (services_update_finished_) {
        LOG(ERROR) << "Cannot delay the start of service '" << service.name()
                   << "' because all services are already updated. Ignoring.";
        return;
    }
    delayed_service_names_.emplace_back(service.name());
}

Result<Success> ServiceParser::ParseSection(std::vector<std::string>&& args,
                                            const std::string& filename, int line) {
    if (args.size() < 3) {
        return Error() << "services must have a name and a program";
    }

    const std::string& name = args[1];
    if (!IsValidName(name)) {
        return Error() << "invalid service name '" << name << "'";
    }

    filename_ = filename;

    Subcontext* restart_action_subcontext = nullptr;
    if (subcontexts_) {
        for (auto& subcontext : *subcontexts_) {
            if (StartsWith(filename, subcontext.path_prefix())) {
                restart_action_subcontext = &subcontext;
                break;
            }
        }
    }

    std::vector<std::string> str_args(args.begin() + 2, args.end());

    if (SelinuxGetVendorAndroidVersion() <= __ANDROID_API_P__) {
        if (str_args[0] == "/sbin/watchdogd") {
            str_args[0] = "/system/bin/watchdogd";
        }
    }

    service_ = std::make_unique<Service>(name, restart_action_subcontext, str_args);
    return Success();
}

Result<Success> ServiceParser::ParseLineSection(std::vector<std::string>&& args, int line) {
    return service_ ? service_->ParseLine(std::move(args)) : Success();
}

Result<Success> ServiceParser::EndSection() {
    if (service_) {
        Service* old_service = service_list_->FindService(service_->name());
        if (old_service) {
            if (!service_->is_override()) {
                return Error() << "ignored duplicate definition of service '" << service_->name()
                               << "'";
            }

            if (StartsWith(filename_, "/apex/") && !old_service->is_updatable()) {
                return Error() << "cannot update a non-updatable service '" << service_->name()
                               << "' with a config in APEX";
            }

            service_list_->RemoveService(*old_service);
            old_service = nullptr;
        }

        service_list_->AddService(std::move(service_));
    }

    return Success();
}

bool ServiceParser::IsValidName(const std::string& name) const {
    // Property names can be any length, but may only contain certain characters.
    // Property values can contain any characters, but may only be a certain length.
    // (The latter restriction is needed because `start` and `stop` work by writing
    // the service name to the "ctl.start" and "ctl.stop" properties.)
    return IsLegalPropertyName("init.svc." + name) && name.size() <= PROP_VALUE_MAX;
}

}  // namespace init
}  // namespace android
