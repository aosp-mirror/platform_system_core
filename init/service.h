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

#ifndef _INIT_SERVICE_H
#define _INIT_SERVICE_H

#include <signal.h>
#include <sys/resource.h>
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
#include "descriptors.h"
#include "keyword_map.h"
#include "parser.h"
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
  public:
    Service(const std::string& name, Subcontext* subcontext_for_restart_commands,
            const std::vector<std::string>& args);

    Service(const std::string& name, unsigned flags, uid_t uid, gid_t gid,
            const std::vector<gid_t>& supp_gids, unsigned namespace_flags,
            const std::string& seclabel, Subcontext* subcontext_for_restart_commands,
            const std::vector<std::string>& args);

    static std::unique_ptr<Service> MakeTemporaryOneshotService(const std::vector<std::string>& args);

    bool IsRunning() { return (flags_ & SVC_RUNNING) != 0; }
    Result<Success> ParseLine(std::vector<std::string>&& args);
    Result<Success> ExecStart();
    Result<Success> Start();
    Result<Success> StartIfNotDisabled();
    Result<Success> StartIfPostData();
    Result<Success> Enable();
    void Reset();
    void ResetIfPostData();
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

    static bool is_exec_service_running() { return is_exec_service_running_; }

    const std::string& name() const { return name_; }
    const std::set<std::string>& classnames() const { return classnames_; }
    unsigned flags() const { return flags_; }
    pid_t pid() const { return pid_; }
    android::base::boot_clock::time_point time_started() const { return time_started_; }
    int crash_count() const { return crash_count_; }
    uid_t uid() const { return uid_; }
    gid_t gid() const { return gid_; }
    unsigned namespace_flags() const { return namespace_flags_; }
    const std::vector<gid_t>& supp_gids() const { return supp_gids_; }
    const std::string& seclabel() const { return seclabel_; }
    const std::vector<int>& keycodes() const { return keycodes_; }
    IoSchedClass ioprio_class() const { return ioprio_class_; }
    int ioprio_pri() const { return ioprio_pri_; }
    const std::set<std::string>& interfaces() const { return interfaces_; }
    int priority() const { return priority_; }
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

  private:
    using OptionParser = Result<Success> (Service::*)(std::vector<std::string>&& args);
    class OptionParserMap;

    Result<Success> SetUpMountNamespace() const;
    Result<Success> SetUpPidNamespace() const;
    Result<Success> EnterNamespaces() const;
    void NotifyStateChange(const std::string& new_state) const;
    void StopOrReset(int how);
    void ZapStdio() const;
    void OpenConsole() const;
    void KillProcessGroup(int signal);
    void SetProcessAttributes();

    Result<Success> ParseCapabilities(std::vector<std::string>&& args);
    Result<Success> ParseClass(std::vector<std::string>&& args);
    Result<Success> ParseConsole(std::vector<std::string>&& args);
    Result<Success> ParseCritical(std::vector<std::string>&& args);
    Result<Success> ParseDisabled(std::vector<std::string>&& args);
    Result<Success> ParseEnterNamespace(std::vector<std::string>&& args);
    Result<Success> ParseGroup(std::vector<std::string>&& args);
    Result<Success> ParsePriority(std::vector<std::string>&& args);
    Result<Success> ParseInterface(std::vector<std::string>&& args);
    Result<Success> ParseIoprio(std::vector<std::string>&& args);
    Result<Success> ParseKeycodes(std::vector<std::string>&& args);
    Result<Success> ParseOneshot(std::vector<std::string>&& args);
    Result<Success> ParseOnrestart(std::vector<std::string>&& args);
    Result<Success> ParseOomScoreAdjust(std::vector<std::string>&& args);
    Result<Success> ParseOverride(std::vector<std::string>&& args);
    Result<Success> ParseMemcgLimitInBytes(std::vector<std::string>&& args);
    Result<Success> ParseMemcgLimitPercent(std::vector<std::string>&& args);
    Result<Success> ParseMemcgLimitProperty(std::vector<std::string>&& args);
    Result<Success> ParseMemcgSoftLimitInBytes(std::vector<std::string>&& args);
    Result<Success> ParseMemcgSwappiness(std::vector<std::string>&& args);
    Result<Success> ParseNamespace(std::vector<std::string>&& args);
    Result<Success> ParseProcessRlimit(std::vector<std::string>&& args);
    Result<Success> ParseRestartPeriod(std::vector<std::string>&& args);
    Result<Success> ParseSeclabel(std::vector<std::string>&& args);
    Result<Success> ParseSetenv(std::vector<std::string>&& args);
    Result<Success> ParseShutdown(std::vector<std::string>&& args);
    Result<Success> ParseSigstop(std::vector<std::string>&& args);
    Result<Success> ParseSocket(std::vector<std::string>&& args);
    Result<Success> ParseTimeoutPeriod(std::vector<std::string>&& args);
    Result<Success> ParseFile(std::vector<std::string>&& args);
    Result<Success> ParseUser(std::vector<std::string>&& args);
    Result<Success> ParseWritepid(std::vector<std::string>&& args);
    Result<Success> ParseUpdatable(std::vector<std::string>&& args);

    template <typename T>
    Result<Success> AddDescriptor(std::vector<std::string>&& args);

    static unsigned long next_start_order_;
    static bool is_exec_service_running_;

    std::string name_;
    std::set<std::string> classnames_;
    std::string console_;

    unsigned flags_;
    pid_t pid_;
    android::base::boot_clock::time_point time_started_;  // time of last start
    android::base::boot_clock::time_point time_crashed_;  // first crash within inspection window
    int crash_count_;                     // number of times crashed within window

    uid_t uid_;
    gid_t gid_;
    std::vector<gid_t> supp_gids_;
    std::optional<CapSet> capabilities_;
    unsigned namespace_flags_;
    // Pair of namespace type, path to namespace.
    std::vector<std::pair<int, std::string>> namespaces_to_enter_;

    std::string seclabel_;

    std::vector<std::unique_ptr<DescriptorInfo>> descriptors_;
    std::vector<std::pair<std::string, std::string>> environment_vars_;

    Action onrestart_;  // Commands to execute on restart.

    std::vector<std::string> writepid_files_;

    std::set<std::string> interfaces_;  // e.g. some.package.foo@1.0::IBaz/instance-name

    // keycodes for triggering this service via /dev/input/input*
    std::vector<int> keycodes_;

    IoSchedClass ioprio_class_;
    int ioprio_pri_;
    int priority_;

    int oom_score_adjust_;

    int swappiness_ = -1;
    int soft_limit_in_bytes_ = -1;

    int limit_in_bytes_ = -1;
    int limit_percent_ = -1;
    std::string limit_property_;

    bool process_cgroup_empty_ = false;

    bool override_ = false;

    unsigned long start_order_;

    std::vector<std::pair<int, rlimit>> rlimits_;

    bool sigstop_ = false;

    std::chrono::seconds restart_period_ = 5s;
    std::optional<std::chrono::seconds> timeout_period_;

    bool updatable_ = false;

    std::vector<std::string> args_;

    std::vector<std::function<void(const siginfo_t& siginfo)>> reap_callbacks_;

    bool pre_apexd_ = false;

    bool post_data_ = false;

    bool running_at_post_data_reset_ = false;
};

class ServiceList {
  public:
    static ServiceList& GetInstance();

    // Exposed for testing
    ServiceList();

    void AddService(std::unique_ptr<Service> service);
    void RemoveService(const Service& svc);

    template <typename T, typename F = decltype(&Service::name)>
    Service* FindService(T value, F function = &Service::name) const {
        auto svc = std::find_if(services_.begin(), services_.end(),
                                [&function, &value](const std::unique_ptr<Service>& s) {
                                    return std::invoke(function, s) == value;
                                });
        if (svc != services_.end()) {
            return svc->get();
        }
        return nullptr;
    }

    Service* FindInterface(const std::string& interface_name) {
        for (const auto& svc : services_) {
            if (svc->interfaces().count(interface_name) > 0) {
                return svc.get();
            }
        }

        return nullptr;
    }

    void DumpState() const;

    auto begin() const { return services_.begin(); }
    auto end() const { return services_.end(); }
    const std::vector<std::unique_ptr<Service>>& services() const { return services_; }
    const std::vector<Service*> services_in_shutdown_order() const;

    void MarkPostData();
    bool IsPostData();
    void MarkServicesUpdate();
    bool IsServicesUpdated() const { return services_update_finished_; }
    void DelayService(const Service& service);

  private:
    std::vector<std::unique_ptr<Service>> services_;

    bool post_data_ = false;
    bool services_update_finished_ = false;
    std::vector<std::string> delayed_service_names_;
};

class ServiceParser : public SectionParser {
  public:
    ServiceParser(ServiceList* service_list, std::vector<Subcontext>* subcontexts)
        : service_list_(service_list), subcontexts_(subcontexts), service_(nullptr) {}
    Result<Success> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                 int line) override;
    Result<Success> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<Success> EndSection() override;
    void EndFile() override { filename_ = ""; }

  private:
    bool IsValidName(const std::string& name) const;

    ServiceList* service_list_;
    std::vector<Subcontext>* subcontexts_;
    std::unique_ptr<Service> service_;
    std::string filename_;
};

}  // namespace init
}  // namespace android

#endif
