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

#pragma once

#include <signal.h>
#include <sys/types.h>

#include <chrono>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <cutils/iosched_policy.h>

#include "action.h"
#include "capabilities.h"
#include "keyword_map.h"
#include "parser.h"
#include "service_utils.h"
#include "subcontext.h"

#define SVC_DISABLED 0x001        // do not autostart with class
#define SVC_ONESHOT 0x002         // do not restart on exit
#define SVC_RUNNING 0x004         // currently active
#define SVC_RESTARTING 0x008      // waiting to restart
#define SVC_CONSOLE 0x010         // requires console
#define SVC_CRITICAL 0x020        // will reboot into bootloader if keeps crashing
#define SVC_RESET 0x040           // Use when stopping a process,
                                  // but not disabling so it can be restarted with its class.
#define SVC_RC_DISABLED 0x080     // Remember if the disabled flag was set in the rc script.
#define SVC_RESTART 0x100         // Use to safely restart (stop, wait, start) a service.
#define SVC_DISABLED_START 0x200  // A start was requested but it was disabled at the time.
#define SVC_EXEC 0x400  // This service was started by either 'exec' or 'exec_start' and stops
                        // init from processing more commands until it completes

#define SVC_SHUTDOWN_CRITICAL 0x800  // This service is critical for shutdown and
                                     // should not be killed during shutdown
#define SVC_TEMPORARY 0x1000  // This service was started by 'exec' and should be removed from the
                              // service list once it is reaped.

#define NR_SVC_SUPP_GIDS 12    // twelve supplementary groups

namespace android {
namespace init {

class Service {
    friend class ServiceParser;

  public:
    Service(const std::string& name, Subcontext* subcontext_for_restart_commands,
            const std::vector<std::string>& args, bool from_apex = false);

    Service(const std::string& name, unsigned flags, uid_t uid, gid_t gid,
            const std::vector<gid_t>& supp_gids, int namespace_flags, const std::string& seclabel,
            Subcontext* subcontext_for_restart_commands, const std::vector<std::string>& args,
            bool from_apex = false);

    static Result<std::unique_ptr<Service>> MakeTemporaryOneshotService(
            const std::vector<std::string>& args);

    bool IsRunning() { return (flags_ & SVC_RUNNING) != 0; }
    bool IsEnabled() { return (flags_ & SVC_DISABLED) == 0; }
    Result<void> ExecStart();
    Result<void> Start();
    Result<void> StartIfNotDisabled();
    Result<void> Enable();
    void Reset();
    void Stop();
    void Terminate();
    void Timeout();
    void Restart();
    void Reap(const siginfo_t& siginfo);
    void DumpState() const;
    void SetShutdownCritical() { flags_ |= SVC_SHUTDOWN_CRITICAL; }
    bool IsShutdownCritical() const { return (flags_ & SVC_SHUTDOWN_CRITICAL) != 0; }
    void UnSetExec() {
        is_exec_service_running_ = false;
        flags_ &= ~SVC_EXEC;
    }
    void AddReapCallback(std::function<void(const siginfo_t& siginfo)> callback) {
        reap_callbacks_.emplace_back(std::move(callback));
    }
    void SetStartedInFirstStage(pid_t pid);
    bool MarkSocketPersistent(const std::string& socket_name);
    size_t CheckAllCommands() const { return onrestart_.CheckAllCommands(); }

    static bool is_exec_service_running() { return is_exec_service_running_; }
    static pid_t exec_service_pid() { return exec_service_pid_; }
    static std::chrono::time_point<std::chrono::steady_clock> exec_service_started() {
        return exec_service_started_;
    }

    const std::string& name() const { return name_; }
    const std::set<std::string>& classnames() const { return classnames_; }
    unsigned flags() const { return flags_; }
    pid_t pid() const { return pid_; }
    android::base::boot_clock::time_point time_started() const { return time_started_; }
    int crash_count() const { return crash_count_; }
    uid_t uid() const { return proc_attr_.uid; }
    gid_t gid() const { return proc_attr_.gid; }
    int namespace_flags() const { return namespaces_.flags; }
    const std::vector<gid_t>& supp_gids() const { return proc_attr_.supp_gids; }
    const std::string& seclabel() const { return seclabel_; }
    const std::vector<int>& keycodes() const { return keycodes_; }
    IoSchedClass ioprio_class() const { return proc_attr_.ioprio_class; }
    int ioprio_pri() const { return proc_attr_.ioprio_pri; }
    const std::set<std::string>& interfaces() const { return interfaces_; }
    int priority() const { return proc_attr_.priority; }
    int oom_score_adjust() const { return oom_score_adjust_; }
    bool is_override() const { return override_; }
    bool process_cgroup_empty() const { return process_cgroup_empty_; }
    unsigned long start_order() const { return start_order_; }
    void set_sigstop(bool value) { sigstop_ = value; }
    std::chrono::seconds restart_period() const { return restart_period_; }
    std::optional<std::chrono::seconds> timeout_period() const { return timeout_period_; }
    const std::vector<std::string>& args() const { return args_; }
    bool is_updatable() const { return updatable_; }
    bool is_post_data() const { return post_data_; }
    bool is_from_apex() const { return from_apex_; }
    void set_oneshot(bool value) {
        if (value) {
            flags_ |= SVC_ONESHOT;
        } else {
            flags_ &= ~SVC_ONESHOT;
        }
    }
    Subcontext* subcontext() const { return subcontext_; }

  private:
    void NotifyStateChange(const std::string& new_state) const;
    void StopOrReset(int how);
    void KillProcessGroup(int signal, bool report_oneshot = false);
    void SetProcessAttributesAndCaps();
    void ResetFlagsForStart();
    Result<void> CheckConsole();
    void ConfigureMemcg();
    void RunService(
            const std::optional<MountNamespace>& override_mount_namespace,
            const std::vector<Descriptor>& descriptors,
            std::unique_ptr<std::array<int, 2>, void (*)(const std::array<int, 2>* pipe)> pipefd);

    static unsigned long next_start_order_;
    static bool is_exec_service_running_;
    static std::chrono::time_point<std::chrono::steady_clock> exec_service_started_;
    static pid_t exec_service_pid_;

    std::string name_;
    std::set<std::string> classnames_;

    unsigned flags_;
    pid_t pid_;
    android::base::boot_clock::time_point time_started_;  // time of last start
    android::base::boot_clock::time_point time_crashed_;  // first crash within inspection window
    int crash_count_;                     // number of times crashed within window
    std::chrono::minutes fatal_crash_window_ = 4min;  // fatal() when more than 4 crashes in it
    std::optional<std::string> fatal_reboot_target_;  // reboot target of fatal handler

    std::optional<CapSet> capabilities_;
    ProcessAttributes proc_attr_;
    NamespaceInfo namespaces_;

    std::string seclabel_;

    std::vector<SocketDescriptor> sockets_;
    std::vector<FileDescriptor> files_;
    std::vector<std::pair<std::string, std::string>> environment_vars_;

    Subcontext* subcontext_;
    Action onrestart_;  // Commands to execute on restart.

    std::vector<std::string> writepid_files_;

    std::vector<std::string> task_profiles_;

    std::set<std::string> interfaces_;  // e.g. some.package.foo@1.0::IBaz/instance-name

    // keycodes for triggering this service via /dev/input/input*
    std::vector<int> keycodes_;

    int oom_score_adjust_;

    int swappiness_ = -1;
    int soft_limit_in_bytes_ = -1;

    int limit_in_bytes_ = -1;
    int limit_percent_ = -1;
    std::string limit_property_;

    bool process_cgroup_empty_ = false;

    bool override_ = false;

    unsigned long start_order_;

    bool sigstop_ = false;

    std::chrono::seconds restart_period_ = 5s;
    std::optional<std::chrono::seconds> timeout_period_;

    bool updatable_ = false;

    std::vector<std::string> args_;

    std::vector<std::function<void(const siginfo_t& siginfo)>> reap_callbacks_;

    bool use_bootstrap_ns_ = false;

    bool post_data_ = false;

    std::optional<std::string> on_failure_reboot_target_;

    bool from_apex_ = false;
};

}  // namespace init
}  // namespace android
