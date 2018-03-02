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

#include <sys/resource.h>
#include <sys/types.h>

#include <memory>
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
#define SVC_CRITICAL 0x020        // will reboot into recovery if keeps crashing
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
            const std::vector<gid_t>& supp_gids, const CapSet& capabilities,
            unsigned namespace_flags, const std::string& seclabel,
            Subcontext* subcontext_for_restart_commands, const std::vector<std::string>& args);

    static std::unique_ptr<Service> MakeTemporaryOneshotService(const std::vector<std::string>& args);

    bool IsRunning() { return (flags_ & SVC_RUNNING) != 0; }
    Result<Success> ParseLine(const std::vector<std::string>& args);
    Result<Success> ExecStart();
    Result<Success> Start();
    Result<Success> StartIfNotDisabled();
    Result<Success> Enable();
    void Reset();
    void Stop();
    void Terminate();
    void Restart();
    void Reap();
    void DumpState() const;
    void SetShutdownCritical() { flags_ |= SVC_SHUTDOWN_CRITICAL; }
    bool IsShutdownCritical() const { return (flags_ & SVC_SHUTDOWN_CRITICAL) != 0; }
    void UnSetExec() {
        is_exec_service_running_ = false;
        flags_ &= ~SVC_EXEC;
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
    int keychord_id() const { return keychord_id_; }
    void set_keychord_id(int keychord_id) { keychord_id_ = keychord_id; }
    IoSchedClass ioprio_class() const { return ioprio_class_; }
    int ioprio_pri() const { return ioprio_pri_; }
    const std::set<std::string>& interfaces() const { return interfaces_; }
    int priority() const { return priority_; }
    int oom_score_adjust() const { return oom_score_adjust_; }
    bool is_override() const { return override_; }
    bool process_cgroup_empty() const { return process_cgroup_empty_; }
    unsigned long start_order() const { return start_order_; }
    const std::vector<std::string>& args() const { return args_; }

  private:
    using OptionParser = Result<Success> (Service::*)(const std::vector<std::string>& args);
    class OptionParserMap;

    void NotifyStateChange(const std::string& new_state) const;
    void StopOrReset(int how);
    void ZapStdio() const;
    void OpenConsole() const;
    void KillProcessGroup(int signal);
    void SetProcessAttributes();

    Result<Success> ParseCapabilities(const std::vector<std::string>& args);
    Result<Success> ParseClass(const std::vector<std::string>& args);
    Result<Success> ParseConsole(const std::vector<std::string>& args);
    Result<Success> ParseCritical(const std::vector<std::string>& args);
    Result<Success> ParseDisabled(const std::vector<std::string>& args);
    Result<Success> ParseGroup(const std::vector<std::string>& args);
    Result<Success> ParsePriority(const std::vector<std::string>& args);
    Result<Success> ParseInterface(const std::vector<std::string>& args);
    Result<Success> ParseIoprio(const std::vector<std::string>& args);
    Result<Success> ParseKeycodes(const std::vector<std::string>& args);
    Result<Success> ParseOneshot(const std::vector<std::string>& args);
    Result<Success> ParseOnrestart(const std::vector<std::string>& args);
    Result<Success> ParseOomScoreAdjust(const std::vector<std::string>& args);
    Result<Success> ParseOverride(const std::vector<std::string>& args);
    Result<Success> ParseMemcgLimitInBytes(const std::vector<std::string>& args);
    Result<Success> ParseMemcgSoftLimitInBytes(const std::vector<std::string>& args);
    Result<Success> ParseMemcgSwappiness(const std::vector<std::string>& args);
    Result<Success> ParseNamespace(const std::vector<std::string>& args);
    Result<Success> ParseProcessRlimit(const std::vector<std::string>& args);
    Result<Success> ParseSeclabel(const std::vector<std::string>& args);
    Result<Success> ParseSetenv(const std::vector<std::string>& args);
    Result<Success> ParseShutdown(const std::vector<std::string>& args);
    Result<Success> ParseSocket(const std::vector<std::string>& args);
    Result<Success> ParseFile(const std::vector<std::string>& args);
    Result<Success> ParseUser(const std::vector<std::string>& args);
    Result<Success> ParseWritepid(const std::vector<std::string>& args);

    template <typename T>
    Result<Success> AddDescriptor(const std::vector<std::string>& args);

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
    CapSet capabilities_;
    unsigned namespace_flags_;

    std::string seclabel_;

    std::vector<std::unique_ptr<DescriptorInfo>> descriptors_;
    std::vector<std::pair<std::string, std::string>> environment_vars_;

    Action onrestart_;  // Commands to execute on restart.

    std::vector<std::string> writepid_files_;

    std::set<std::string> interfaces_;  // e.g. some.package.foo@1.0::IBaz/instance-name

    // keycodes for triggering this service via /dev/keychord
    std::vector<int> keycodes_;
    int keychord_id_;

    IoSchedClass ioprio_class_;
    int ioprio_pri_;
    int priority_;

    int oom_score_adjust_;

    int swappiness_;
    int soft_limit_in_bytes_;
    int limit_in_bytes_;

    bool process_cgroup_empty_ = false;

    bool override_ = false;

    unsigned long start_order_;

    std::vector<std::pair<int, rlimit>> rlimits_;

    std::vector<std::string> args_;
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

    void DumpState() const;

    auto begin() const { return services_.begin(); }
    auto end() const { return services_.end(); }
    const std::vector<std::unique_ptr<Service>>& services() const { return services_; }
    const std::vector<Service*> services_in_shutdown_order() const;

  private:
    std::vector<std::unique_ptr<Service>> services_;
};

class ServiceParser : public SectionParser {
  public:
    ServiceParser(ServiceList* service_list, std::vector<Subcontext>* subcontexts)
        : service_list_(service_list), subcontexts_(subcontexts), service_(nullptr) {}
    Result<Success> ParseSection(std::vector<std::string>&& args, const std::string& filename,
                                 int line) override;
    Result<Success> ParseLineSection(std::vector<std::string>&& args, int line) override;
    Result<Success> EndSection() override;

  private:
    bool IsValidName(const std::string& name) const;

    ServiceList* service_list_;
    std::vector<Subcontext>* subcontexts_;
    std::unique_ptr<Service> service_;
};

}  // namespace init
}  // namespace android

#endif
