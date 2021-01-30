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
#include <linux/securebits.h>
#include <sched.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <termios.h>
#include <unistd.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>
#include <processgroup/processgroup.h>
#include <selinux/selinux.h>

#include "lmkd_service.h"
#include "service_list.h"
#include "util.h"

#ifdef INIT_FULL_SOURCES
#include <ApexProperties.sysprop.h>
#include <android/api-level.h>

#include "mount_namespace.h"
#include "reboot_utils.h"
#include "selinux.h"
#else
#include "host_init_stubs.h"
#endif

using android::base::boot_clock;
using android::base::GetBoolProperty;
using android::base::GetProperty;
using android::base::Join;
using android::base::make_scope_guard;
using android::base::SetProperty;
using android::base::StartsWith;
using android::base::StringPrintf;
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
    std::unique_ptr<char, decltype(&freecon)> mycon(raw_con, freecon);

    if (getfilecon(service_path.c_str(), &raw_filecon) == -1) {
        return Error() << "Could not get file context";
    }
    std::unique_ptr<char, decltype(&freecon)> filecon(raw_filecon, freecon);

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
                          "device-policy#label_new_services_and_address_denials. Note: this "
                          "error shows up even in permissive mode in order to make auditing "
                          "denials possible.";
    }
    if (rc < 0) {
        return Error() << "Could not get process context";
    }
    return computed_context;
}

static bool ExpandArgsAndExecv(const std::vector<std::string>& args, bool sigstop) {
    std::vector<std::string> expanded_args;
    std::vector<char*> c_strings;

    expanded_args.resize(args.size());
    c_strings.push_back(const_cast<char*>(args[0].data()));
    for (std::size_t i = 1; i < args.size(); ++i) {
        auto expanded_arg = ExpandProps(args[i]);
        if (!expanded_arg.ok()) {
            LOG(FATAL) << args[0] << ": cannot expand arguments': " << expanded_arg.error();
        }
        expanded_args[i] = *expanded_arg;
        c_strings.push_back(expanded_args[i].data());
    }
    c_strings.push_back(nullptr);

    if (sigstop) {
        kill(getpid(), SIGSTOP);
    }

    return execv(c_strings[0], c_strings.data()) == 0;
}

static bool AreRuntimeApexesReady() {
    struct stat buf;
    return stat("/apex/com.android.runtime/", &buf) == 0;
}

unsigned long Service::next_start_order_ = 1;
bool Service::is_exec_service_running_ = false;

Service::Service(const std::string& name, Subcontext* subcontext_for_restart_commands,
                 const std::vector<std::string>& args, bool from_apex)
    : Service(name, 0, 0, 0, {}, 0, "", subcontext_for_restart_commands, args, from_apex) {}

Service::Service(const std::string& name, unsigned flags, uid_t uid, gid_t gid,
                 const std::vector<gid_t>& supp_gids, int namespace_flags,
                 const std::string& seclabel, Subcontext* subcontext_for_restart_commands,
                 const std::vector<std::string>& args, bool from_apex)
    : name_(name),
      classnames_({"default"}),
      flags_(flags),
      pid_(0),
      crash_count_(0),
      proc_attr_{.ioprio_class = IoSchedClass_NONE,
                 .ioprio_pri = 0,
                 .uid = uid,
                 .gid = gid,
                 .supp_gids = supp_gids,
                 .priority = 0},
      namespaces_{.flags = namespace_flags},
      seclabel_(seclabel),
      subcontext_(subcontext_for_restart_commands),
      onrestart_(false, subcontext_for_restart_commands, "<Service '" + name + "' onrestart>", 0,
                 "onrestart", {}),
      oom_score_adjust_(DEFAULT_OOM_SCORE_ADJUST),
      start_order_(0),
      args_(args),
      from_apex_(from_apex) {}

void Service::NotifyStateChange(const std::string& new_state) const {
    if ((flags_ & SVC_TEMPORARY) != 0) {
        // Services created by 'exec' are temporary and don't have properties tracking their state.
        return;
    }

    std::string prop_name = "init.svc." + name_;
    SetProperty(prop_name, new_state);

    if (new_state == "running") {
        uint64_t start_ns = time_started_.time_since_epoch().count();
        std::string boottime_property = "ro.boottime." + name_;
        if (GetProperty(boottime_property, "").empty()) {
            SetProperty(boottime_property, std::to_string(start_ns));
        }
    }

    // init.svc_debug_pid.* properties are only for tests, and should not be used
    // on device for security checks.
    std::string pid_property = "init.svc_debug_pid." + name_;
    if (new_state == "running") {
        SetProperty(pid_property, std::to_string(pid_));
    } else if (new_state == "stopped") {
        SetProperty(pid_property, "");
    }
}

void Service::KillProcessGroup(int signal, bool report_oneshot) {
    // If we've already seen a successful result from killProcessGroup*(), then we have removed
    // the cgroup already and calling these functions a second time will simply result in an error.
    // This is true regardless of which signal was sent.
    // These functions handle their own logging, so no additional logging is needed.
    if (!process_cgroup_empty_) {
        LOG(INFO) << "Sending signal " << signal << " to service '" << name_ << "' (pid " << pid_
                  << ") process group...";
        int max_processes = 0;
        int r;
        if (signal == SIGTERM) {
            r = killProcessGroupOnce(proc_attr_.uid, pid_, signal, &max_processes);
        } else {
            r = killProcessGroup(proc_attr_.uid, pid_, signal, &max_processes);
        }

        if (report_oneshot && max_processes > 0) {
            LOG(WARNING)
                    << "Killed " << max_processes
                    << " additional processes from a oneshot process group for service '" << name_
                    << "'. This is new behavior, previously child processes would not be killed in "
                       "this case.";
        }

        if (r == 0) process_cgroup_empty_ = true;
    }

    if (oom_score_adjust_ != DEFAULT_OOM_SCORE_ADJUST) {
        LmkdUnregister(name_, pid_);
    }
}

void Service::SetProcessAttributesAndCaps() {
    // Keep capabilites on uid change.
    if (capabilities_ && proc_attr_.uid) {
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

    if (auto result = SetProcessAttributes(proc_attr_); !result.ok()) {
        LOG(FATAL) << "cannot set attribute for " << name_ << ": " << result.error();
    }

    if (!seclabel_.empty()) {
        if (setexeccon(seclabel_.c_str()) < 0) {
            PLOG(FATAL) << "cannot setexeccon('" << seclabel_ << "') for " << name_;
        }
    }

    if (capabilities_) {
        if (!SetCapsForExec(*capabilities_)) {
            LOG(FATAL) << "cannot set capabilities for " << name_;
        }
    } else if (proc_attr_.uid) {
        // Inheritable caps can be non-zero when running in a container.
        if (!DropInheritableCaps()) {
            LOG(FATAL) << "cannot drop inheritable caps for " << name_;
        }
    }
}

void Service::Reap(const siginfo_t& siginfo) {
    if (!(flags_ & SVC_ONESHOT) || (flags_ & SVC_RESTART)) {
        KillProcessGroup(SIGKILL, false);
    } else {
        // Legacy behavior from ~2007 until Android R: this else branch did not exist and we did not
        // kill the process group in this case.
        if (SelinuxGetVendorAndroidVersion() >= __ANDROID_API_R__) {
            // The new behavior in Android R is to kill these process groups in all cases.  The
            // 'true' parameter instructions KillProcessGroup() to report a warning message where it
            // detects a difference in behavior has occurred.
            KillProcessGroup(SIGKILL, true);
        }
    }

    // Remove any socket resources we may have created.
    for (const auto& socket : sockets_) {
        auto path = ANDROID_SOCKET_DIR "/" + socket.name;
        unlink(path.c_str());
    }

    for (const auto& f : reap_callbacks_) {
        f(siginfo);
    }

    if ((siginfo.si_code != CLD_EXITED || siginfo.si_status != 0) && on_failure_reboot_target_) {
        LOG(ERROR) << "Service with 'reboot_on_failure' option failed, shutting down system.";
        trigger_shutdown(*on_failure_reboot_target_);
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

#if INIT_FULL_SOURCES
    static bool is_apex_updatable = android::sysprop::ApexProperties::updatable().value_or(false);
#else
    static bool is_apex_updatable = false;
#endif
    const bool is_process_updatable = !pre_apexd_ && is_apex_updatable;

    // If we crash > 4 times in 'fatal_crash_window_' minutes or before boot_completed,
    // reboot into bootloader or set crashing property
    boot_clock::time_point now = boot_clock::now();
    if (((flags_ & SVC_CRITICAL) || is_process_updatable) && !(flags_ & SVC_RESTART)) {
        bool boot_completed = GetBoolProperty("sys.boot_completed", false);
        if (now < time_crashed_ + fatal_crash_window_ || !boot_completed) {
            if (++crash_count_ > 4) {
                auto exit_reason = boot_completed ?
                    "in " + std::to_string(fatal_crash_window_.count()) + " minutes" :
                    "before boot completed";
                if (flags_ & SVC_CRITICAL) {
                    if (!GetBoolProperty("init.svc_debug.no_fatal." + name_, false)) {
                        // Aborts into `fatal_reboot_target_'.
                        SetFatalRebootTarget(fatal_reboot_target_);
                        LOG(FATAL) << "critical process '" << name_ << "' exited 4 times "
                                   << exit_reason;
                    }
                } else {
                    LOG(ERROR) << "process with updatable components '" << name_
                               << "' exited 4 times " << exit_reason;
                    // Notifies update_verifier and apexd
                    SetProperty("sys.init.updatable_crashing_process_name", name_);
                    SetProperty("sys.init.updatable_crashing", "1");
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
    for (const auto& socket : sockets_) {
        LOG(INFO) << "  socket " << socket.name;
    }
    for (const auto& file : files_) {
        LOG(INFO) << "  file " << file.name;
    }
}


Result<void> Service::ExecStart() {
    auto reboot_on_failure = make_scope_guard([this] {
        if (on_failure_reboot_target_) {
            trigger_shutdown(*on_failure_reboot_target_);
        }
    });

    if (is_updatable() && !ServiceList::GetInstance().IsServicesUpdated()) {
        // Don't delay the service for ExecStart() as the semantic is that
        // the caller might depend on the side effect of the execution.
        return Error() << "Cannot start an updatable service '" << name_
                       << "' before configs from APEXes are all loaded";
    }

    flags_ |= SVC_ONESHOT;

    if (auto result = Start(); !result.ok()) {
        return result;
    }

    flags_ |= SVC_EXEC;
    is_exec_service_running_ = true;

    LOG(INFO) << "SVC_EXEC service '" << name_ << "' pid " << pid_ << " (uid " << proc_attr_.uid
              << " gid " << proc_attr_.gid << "+" << proc_attr_.supp_gids.size() << " context "
              << (!seclabel_.empty() ? seclabel_ : "default") << ") started; waiting...";

    reboot_on_failure.Disable();
    return {};
}

Result<void> Service::Start() {
    auto reboot_on_failure = make_scope_guard([this] {
        if (on_failure_reboot_target_) {
            trigger_shutdown(*on_failure_reboot_target_);
        }
    });

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
        reboot_on_failure.Disable();
        return {};
    }

    bool needs_console = (flags_ & SVC_CONSOLE);
    if (needs_console) {
        if (proc_attr_.console.empty()) {
            proc_attr_.console = "/dev/" + GetProperty("ro.boot.console", "console");
        }

        // Make sure that open call succeeds to ensure a console driver is
        // properly registered for the device node
        int console_fd = open(proc_attr_.console.c_str(), O_RDWR | O_CLOEXEC);
        if (console_fd < 0) {
            flags_ |= SVC_DISABLED;
            return ErrnoError() << "Couldn't open console '" << proc_attr_.console << "'";
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
        if (!result.ok()) {
            return result.error();
        }
        scon = *result;
    }

    if (!AreRuntimeApexesReady() && !pre_apexd_) {
        // If this service is started before the Runtime and ART APEXes get
        // available, mark it as pre-apexd one. Note that this marking is
        // permanent. So for example, if the service is re-launched (e.g., due
        // to crash), it is still recognized as pre-apexd... for consistency.
        pre_apexd_ = true;
    }

    // For pre-apexd services, override mount namespace as "bootstrap" one before starting.
    // Note: "ueventd" is supposed to be run in "default" mount namespace even if it's pre-apexd
    // to support loading firmwares from APEXes.
    std::optional<MountNamespace> override_mount_namespace;
    if (name_ == "ueventd") {
        override_mount_namespace = NS_DEFAULT;
    } else if (pre_apexd_) {
        override_mount_namespace = NS_BOOTSTRAP;
    }

    post_data_ = ServiceList::GetInstance().IsPostData();

    LOG(INFO) << "starting service '" << name_ << "'...";

    std::vector<Descriptor> descriptors;
    for (const auto& socket : sockets_) {
        if (auto result = socket.Create(scon); result.ok()) {
            descriptors.emplace_back(std::move(*result));
        } else {
            LOG(INFO) << "Could not create socket '" << socket.name << "': " << result.error();
        }
    }

    for (const auto& file : files_) {
        if (auto result = file.Create(); result.ok()) {
            descriptors.emplace_back(std::move(*result));
        } else {
            LOG(INFO) << "Could not open file '" << file.name << "': " << result.error();
        }
    }

    pid_t pid = -1;
    if (namespaces_.flags) {
        pid = clone(nullptr, nullptr, namespaces_.flags | SIGCHLD, nullptr);
    } else {
        pid = fork();
    }

    if (pid == 0) {
        umask(077);

        if (auto result = EnterNamespaces(namespaces_, name_, override_mount_namespace);
            !result.ok()) {
            LOG(FATAL) << "Service '" << name_
                       << "' failed to set up namespaces: " << result.error();
        }

        for (const auto& [key, value] : environment_vars_) {
            setenv(key.c_str(), value.c_str(), 1);
        }

        for (const auto& descriptor : descriptors) {
            descriptor.Publish();
        }

        if (auto result = WritePidToFiles(&writepid_files_); !result.ok()) {
            LOG(ERROR) << "failed to write pid to files: " << result.error();
        }

        if (task_profiles_.size() > 0 && !SetTaskProfiles(getpid(), task_profiles_)) {
            LOG(ERROR) << "failed to set task profiles";
        }

        // As requested, set our gid, supplemental gids, uid, context, and
        // priority. Aborts on failure.
        SetProcessAttributesAndCaps();

        if (!ExpandArgsAndExecv(args_, sigstop_)) {
            PLOG(ERROR) << "cannot execv('" << args_[0]
                        << "'). See the 'Debugging init' section of init's README.md for tips";
        }

        _exit(127);
    }

    if (pid < 0) {
        pid_ = 0;
        return ErrnoError() << "Failed to fork";
    }

    if (oom_score_adjust_ != DEFAULT_OOM_SCORE_ADJUST) {
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
    errno = -createProcessGroup(proc_attr_.uid, pid_, use_memcg);
    if (errno != 0) {
        PLOG(ERROR) << "createProcessGroup(" << proc_attr_.uid << ", " << pid_
                    << ") failed for service '" << name_ << "'";
    } else if (use_memcg) {
        if (swappiness_ != -1) {
            if (!setProcessGroupSwappiness(proc_attr_.uid, pid_, swappiness_)) {
                PLOG(ERROR) << "setProcessGroupSwappiness failed";
            }
        }

        if (soft_limit_in_bytes_ != -1) {
            if (!setProcessGroupSoftLimit(proc_attr_.uid, pid_, soft_limit_in_bytes_)) {
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
            if (!setProcessGroupLimit(proc_attr_.uid, pid_, computed_limit_in_bytes)) {
                PLOG(ERROR) << "setProcessGroupLimit failed";
            }
        }
    }

    if (oom_score_adjust_ != DEFAULT_OOM_SCORE_ADJUST) {
        LmkdRegister(name_, proc_attr_.uid, pid_, oom_score_adjust_);
    }

    NotifyStateChange("running");
    reboot_on_failure.Disable();
    return {};
}

Result<void> Service::StartIfNotDisabled() {
    if (!(flags_ & SVC_DISABLED)) {
        return Start();
    } else {
        flags_ |= SVC_DISABLED_START;
    }
    return {};
}

Result<void> Service::Enable() {
    flags_ &= ~(SVC_DISABLED | SVC_RC_DISABLED);
    if (flags_ & SVC_DISABLED_START) {
        return Start();
    }
    return {};
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

Result<void> Service::StartIfPostData() {
    // Start the service, but only if it was started after /data was mounted,
    // and it was still running when we reset the post-data services.
    if (running_at_post_data_reset_) {
        return Start();
    }

    return {};
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
        if (auto result = Start(); !result.ok()) {
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

Result<std::unique_ptr<Service>> Service::MakeTemporaryOneshotService(
        const std::vector<std::string>& args) {
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
        return Error() << "exec called with too many supplementary group ids";
    }

    if (command_arg >= args.size()) {
        return Error() << "exec called without command";
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
        if (!uid.ok()) {
            return Error() << "Unable to decode UID for '" << args[2] << "': " << uid.error();
        }
    }
    Result<gid_t> gid = 0;
    std::vector<gid_t> supp_gids;
    if (command_arg > 4) {
        gid = DecodeUid(args[3]);
        if (!gid.ok()) {
            return Error() << "Unable to decode GID for '" << args[3] << "': " << gid.error();
        }
        std::size_t nr_supp_gids = command_arg - 1 /* -- */ - 4 /* exec SECLABEL UID GID */;
        for (size_t i = 0; i < nr_supp_gids; ++i) {
            auto supp_gid = DecodeUid(args[4 + i]);
            if (!supp_gid.ok()) {
                return Error() << "Unable to decode GID for '" << args[4 + i]
                               << "': " << supp_gid.error();
            }
            supp_gids.push_back(*supp_gid);
        }
    }

    return std::make_unique<Service>(name, flags, *uid, *gid, supp_gids, namespace_flags, seclabel,
                                     nullptr, str_args, false);
}

}  // namespace init
}  // namespace android
