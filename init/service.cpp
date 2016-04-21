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
#include <sched.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <selinux/selinux.h>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/android_reboot.h>
#include <cutils/sockets.h>
#include <system/thread_defs.h>

#include <processgroup/processgroup.h>

#include "action.h"
#include "init.h"
#include "init_parser.h"
#include "log.h"
#include "property_service.h"
#include "util.h"

using android::base::StringPrintf;
using android::base::WriteStringToFile;

#define CRITICAL_CRASH_THRESHOLD    4       // if we crash >4 times ...
#define CRITICAL_CRASH_WINDOW       (4*60)  // ... in 4 minutes, goto recovery

static void SetUpPidNamespace(const std::string& service_name) {
    constexpr unsigned int kSafeFlags = MS_NODEV | MS_NOEXEC | MS_NOSUID;

    // It's OK to LOG(FATAL) in this function since it's running in the first
    // child process.
    if (mount("", "/proc", "proc", kSafeFlags | MS_REMOUNT, "") == -1) {
        PLOG(FATAL) << "couldn't remount(/proc)";
    }

    if (prctl(PR_SET_NAME, service_name.c_str()) == -1) {
        PLOG(FATAL) << "couldn't set name";
    }

    pid_t child_pid = fork();
    if (child_pid == -1) {
        PLOG(FATAL) << "couldn't fork init inside the PID namespace";
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
}

SocketInfo::SocketInfo() : uid(0), gid(0), perm(0) {
}

SocketInfo::SocketInfo(const std::string& name, const std::string& type, uid_t uid,
                       gid_t gid, int perm, const std::string& socketcon)
    : name(name), type(type), uid(uid), gid(gid), perm(perm), socketcon(socketcon) {
}

ServiceEnvironmentInfo::ServiceEnvironmentInfo() {
}

ServiceEnvironmentInfo::ServiceEnvironmentInfo(const std::string& name,
                                               const std::string& value)
    : name(name), value(value) {
}

Service::Service(const std::string& name, const std::string& classname,
                 const std::vector<std::string>& args)
    : name_(name), classname_(classname), flags_(0), pid_(0), time_started_(0),
      time_crashed_(0), nr_crashed_(0), uid_(0), gid_(0), namespace_flags_(0),
      seclabel_(""), ioprio_class_(IoSchedClass_NONE), ioprio_pri_(0),
      priority_(0), args_(args) {
    onrestart_.InitSingleTrigger("onrestart");
}

Service::Service(const std::string& name, const std::string& classname,
                 unsigned flags, uid_t uid, gid_t gid,
                 const std::vector<gid_t>& supp_gids, unsigned namespace_flags,
                 const std::string& seclabel,
                 const std::vector<std::string>& args)
    : name_(name), classname_(classname), flags_(flags), pid_(0),
      time_started_(0), time_crashed_(0), nr_crashed_(0), uid_(uid), gid_(gid),
      supp_gids_(supp_gids), namespace_flags_(namespace_flags),
      seclabel_(seclabel), ioprio_class_(IoSchedClass_NONE), ioprio_pri_(0),
      priority_(0), args_(args) {
    onrestart_.InitSingleTrigger("onrestart");
}

void Service::NotifyStateChange(const std::string& new_state) const {
    if ((flags_ & SVC_EXEC) != 0) {
        // 'exec' commands don't have properties tracking their state.
        return;
    }

    std::string prop_name = StringPrintf("init.svc.%s", name_.c_str());
    if (prop_name.length() >= PROP_NAME_MAX) {
        // If the property name would be too long, we can't set it.
        LOG(ERROR) << "Property name \"init.svc." << name_ << "\" too long; not setting to " << new_state;
        return;
    }

    property_set(prop_name.c_str(), new_state.c_str());
}

void Service::KillProcessGroup(int signal) {
    LOG(VERBOSE) << "Sending signal " << signal
                 << " to service '" << name_
                 << "' (pid " << pid_ << ") process group...\n",
    kill(pid_, signal);
    killProcessGroup(uid_, pid_, signal);
}

bool Service::Reap() {
    if (!(flags_ & SVC_ONESHOT) || (flags_ & SVC_RESTART)) {
        KillProcessGroup(SIGKILL);
    }

    // Remove any sockets we may have created.
    for (const auto& si : sockets_) {
        std::string tmp = StringPrintf(ANDROID_SOCKET_DIR "/%s", si.name.c_str());
        unlink(tmp.c_str());
    }

    if (flags_ & SVC_EXEC) {
        LOG(INFO) << "SVC_EXEC pid " << pid_ << " finished...";
        return true;
    }

    pid_ = 0;
    flags_ &= (~SVC_RUNNING);

    // Oneshot processes go into the disabled state on exit,
    // except when manually restarted.
    if ((flags_ & SVC_ONESHOT) && !(flags_ & SVC_RESTART)) {
        flags_ |= SVC_DISABLED;
    }

    // Disabled and reset processes do not get restarted automatically.
    if (flags_ & (SVC_DISABLED | SVC_RESET))  {
        NotifyStateChange("stopped");
        return false;
    }

    time_t now = gettime();
    if ((flags_ & SVC_CRITICAL) && !(flags_ & SVC_RESTART)) {
        if (time_crashed_ + CRITICAL_CRASH_WINDOW >= now) {
            if (++nr_crashed_ > CRITICAL_CRASH_THRESHOLD) {
                LOG(ERROR) << "critical process '" << name_ << "' exited "
                           << CRITICAL_CRASH_THRESHOLD << " times in "
                           << (CRITICAL_CRASH_WINDOW / 60) << " minutes; "
                           << "rebooting into recovery mode";
                android_reboot(ANDROID_RB_RESTART2, 0, "recovery");
                return false;
            }
        } else {
            time_crashed_ = now;
            nr_crashed_ = 1;
        }
    }

    flags_ &= (~SVC_RESTART);
    flags_ |= SVC_RESTARTING;

    // Execute all onrestart commands for this service.
    onrestart_.ExecuteAllCommands();

    NotifyStateChange("restarting");
    return false;
}

void Service::DumpState() const {
    LOG(INFO) << "service " << name_;
    LOG(INFO) << "  class '" << classname_ << "'";
    LOG(INFO) << "  exec "<< android::base::Join(args_, " ");
    for (const auto& si : sockets_) {
        LOG(INFO) << "  socket " << si.name << " " << si.type << " " << std::oct << si.perm;
    }
}

bool Service::HandleClass(const std::vector<std::string>& args, std::string* err) {
    classname_ = args[1];
    return true;
}

bool Service::HandleConsole(const std::vector<std::string>& args, std::string* err) {
    flags_ |= SVC_CONSOLE;
    console_ = args.size() > 1 ? "/dev/" + args[1] : "";
    return true;
}

bool Service::HandleCritical(const std::vector<std::string>& args, std::string* err) {
    flags_ |= SVC_CRITICAL;
    return true;
}

bool Service::HandleDisabled(const std::vector<std::string>& args, std::string* err) {
    flags_ |= SVC_DISABLED;
    flags_ |= SVC_RC_DISABLED;
    return true;
}

bool Service::HandleGroup(const std::vector<std::string>& args, std::string* err) {
    gid_ = decode_uid(args[1].c_str());
    for (std::size_t n = 2; n < args.size(); n++) {
        supp_gids_.emplace_back(decode_uid(args[n].c_str()));
    }
    return true;
}

bool Service::HandlePriority(const std::vector<std::string>& args, std::string* err) {
    priority_ = std::stoi(args[1]);

    if (priority_ < ANDROID_PRIORITY_HIGHEST || priority_ > ANDROID_PRIORITY_LOWEST) {
        priority_ = 0;
        *err = StringPrintf("process priority value must be range %d - %d",
                ANDROID_PRIORITY_HIGHEST, ANDROID_PRIORITY_LOWEST);
        return false;
    }

    return true;
}

bool Service::HandleIoprio(const std::vector<std::string>& args, std::string* err) {
    ioprio_pri_ = std::stoul(args[2], 0, 8);

    if (ioprio_pri_ < 0 || ioprio_pri_ > 7) {
        *err = "priority value must be range 0 - 7";
        return false;
    }

    if (args[1] == "rt") {
        ioprio_class_ = IoSchedClass_RT;
    } else if (args[1] == "be") {
        ioprio_class_ = IoSchedClass_BE;
    } else if (args[1] == "idle") {
        ioprio_class_ = IoSchedClass_IDLE;
    } else {
        *err = "ioprio option usage: ioprio <rt|be|idle> <0-7>";
        return false;
    }

    return true;
}

bool Service::HandleKeycodes(const std::vector<std::string>& args, std::string* err) {
    for (std::size_t i = 1; i < args.size(); i++) {
        keycodes_.emplace_back(std::stoi(args[i]));
    }
    return true;
}

bool Service::HandleOneshot(const std::vector<std::string>& args, std::string* err) {
    flags_ |= SVC_ONESHOT;
    return true;
}

bool Service::HandleOnrestart(const std::vector<std::string>& args, std::string* err) {
    std::vector<std::string> str_args(args.begin() + 1, args.end());
    onrestart_.AddCommand(str_args, "", 0, err);
    return true;
}

bool Service::HandleNamespace(const std::vector<std::string>& args, std::string* err) {
    for (size_t i = 1; i < args.size(); i++) {
        if (args[i] == "pid") {
            namespace_flags_ |= CLONE_NEWPID;
            // PID namespaces require mount namespaces.
            namespace_flags_ |= CLONE_NEWNS;
        } else if (args[i] == "mnt") {
            namespace_flags_ |= CLONE_NEWNS;
        } else {
            *err = "namespace must be 'pid' or 'mnt'";
            return false;
        }
    }
    return true;
}

bool Service::HandleSeclabel(const std::vector<std::string>& args, std::string* err) {
    seclabel_ = args[1];
    return true;
}

bool Service::HandleSetenv(const std::vector<std::string>& args, std::string* err) {
    envvars_.emplace_back(args[1], args[2]);
    return true;
}

/* name type perm [ uid gid context ] */
bool Service::HandleSocket(const std::vector<std::string>& args, std::string* err) {
    if (args[2] != "dgram" && args[2] != "stream" && args[2] != "seqpacket") {
        *err = "socket type must be 'dgram', 'stream' or 'seqpacket'";
        return false;
    }

    int perm = std::stoul(args[3], 0, 8);
    uid_t uid = args.size() > 4 ? decode_uid(args[4].c_str()) : 0;
    gid_t gid = args.size() > 5 ? decode_uid(args[5].c_str()) : 0;
    std::string socketcon = args.size() > 6 ? args[6] : "";

    sockets_.emplace_back(args[1], args[2], uid, gid, perm, socketcon);
    return true;
}

bool Service::HandleUser(const std::vector<std::string>& args, std::string* err) {
    uid_ = decode_uid(args[1].c_str());
    return true;
}

bool Service::HandleWritepid(const std::vector<std::string>& args, std::string* err) {
    writepid_files_.assign(args.begin() + 1, args.end());
    return true;
}

class Service::OptionHandlerMap : public KeywordMap<OptionHandler> {
public:
    OptionHandlerMap() {
    }
private:
    Map& map() const override;
};

Service::OptionHandlerMap::Map& Service::OptionHandlerMap::map() const {
    constexpr std::size_t kMax = std::numeric_limits<std::size_t>::max();
    static const Map option_handlers = {
        {"class",       {1,     1,    &Service::HandleClass}},
        {"console",     {0,     1,    &Service::HandleConsole}},
        {"critical",    {0,     0,    &Service::HandleCritical}},
        {"disabled",    {0,     0,    &Service::HandleDisabled}},
        {"group",       {1,     NR_SVC_SUPP_GIDS + 1, &Service::HandleGroup}},
        {"ioprio",      {2,     2,    &Service::HandleIoprio}},
        {"priority",    {1,     1,    &Service::HandlePriority}},
        {"keycodes",    {1,     kMax, &Service::HandleKeycodes}},
        {"oneshot",     {0,     0,    &Service::HandleOneshot}},
        {"onrestart",   {1,     kMax, &Service::HandleOnrestart}},
        {"namespace",   {1,     2,    &Service::HandleNamespace}},
        {"seclabel",    {1,     1,    &Service::HandleSeclabel}},
        {"setenv",      {2,     2,    &Service::HandleSetenv}},
        {"socket",      {3,     6,    &Service::HandleSocket}},
        {"user",        {1,     1,    &Service::HandleUser}},
        {"writepid",    {1,     kMax, &Service::HandleWritepid}},
    };
    return option_handlers;
}

bool Service::HandleLine(const std::vector<std::string>& args, std::string* err) {
    if (args.empty()) {
        *err = "option needed, but not provided";
        return false;
    }

    static const OptionHandlerMap handler_map;
    auto handler = handler_map.FindFunction(args[0], args.size() - 1, err);

    if (!handler) {
        return false;
    }

    return (this->*handler)(args, err);
}

bool Service::Start() {
    // Starting a service removes it from the disabled or reset state and
    // immediately takes it out of the restarting state if it was in there.
    flags_ &= (~(SVC_DISABLED|SVC_RESTARTING|SVC_RESET|SVC_RESTART|SVC_DISABLED_START));
    time_started_ = 0;

    // Running processes require no additional work --- if they're in the
    // process of exiting, we've ensured that they will immediately restart
    // on exit, unless they are ONESHOT.
    if (flags_ & SVC_RUNNING) {
        return false;
    }

    bool needs_console = (flags_ & SVC_CONSOLE);
    if (needs_console) {
        if (console_.empty()) {
            console_ = default_console;
        }

        bool have_console = (open(console_.c_str(), O_RDWR | O_CLOEXEC) != -1);
        if (!have_console) {
            PLOG(ERROR) << "service '" << name_ << "' couldn't open console '" << console_ << "'";
            flags_ |= SVC_DISABLED;
            return false;
        }
    }

    struct stat sb;
    if (stat(args_[0].c_str(), &sb) == -1) {
        PLOG(ERROR) << "cannot find '" << args_[0] << "', disabling '" << name_ << "'";
        flags_ |= SVC_DISABLED;
        return false;
    }

    std::string scon;
    if (!seclabel_.empty()) {
        scon = seclabel_;
    } else {
        char* mycon = nullptr;
        char* fcon = nullptr;

        LOG(INFO) << "computing context for service '" << args_[0] << "'";
        int rc = getcon(&mycon);
        if (rc < 0) {
            LOG(ERROR) << "could not get context while starting '" << name_ << "'";
            return false;
        }

        rc = getfilecon(args_[0].c_str(), &fcon);
        if (rc < 0) {
            LOG(ERROR) << "could not get file context while starting '" << name_ << "'";
            free(mycon);
            return false;
        }

        char* ret_scon = nullptr;
        rc = security_compute_create(mycon, fcon, string_to_security_class("process"),
                                     &ret_scon);
        if (rc == 0) {
            scon = ret_scon;
            free(ret_scon);
        }
        if (rc == 0 && scon == mycon) {
            LOG(ERROR) << "Service " << name_ << " does not have a SELinux domain defined.";
            free(mycon);
            free(fcon);
            return false;
        }
        free(mycon);
        free(fcon);
        if (rc < 0) {
            LOG(ERROR) << "could not get context while starting '" << name_ << "'";
            return false;
        }
    }

    LOG(VERBOSE) << "Starting service '" << name_ << "'...";

    pid_t pid = -1;
    if (namespace_flags_) {
        pid = clone(nullptr, nullptr, namespace_flags_ | SIGCHLD,
                    nullptr);
    } else {
        pid = fork();
    }

    if (pid == 0) {
        umask(077);

        if (namespace_flags_ & CLONE_NEWPID) {
            // This will fork again to run an init process inside the PID
            // namespace.
            SetUpPidNamespace(name_);
        }

        for (const auto& ei : envvars_) {
            add_environment(ei.name.c_str(), ei.value.c_str());
        }

        for (const auto& si : sockets_) {
            int socket_type = ((si.type == "stream" ? SOCK_STREAM :
                                (si.type == "dgram" ? SOCK_DGRAM :
                                 SOCK_SEQPACKET)));
            const char* socketcon =
                !si.socketcon.empty() ? si.socketcon.c_str() : scon.c_str();

            int s = create_socket(si.name.c_str(), socket_type, si.perm,
                                  si.uid, si.gid, socketcon);
            if (s >= 0) {
                PublishSocket(si.name, s);
            }
        }

        std::string pid_str = StringPrintf("%d", getpid());
        for (const auto& file : writepid_files_) {
            if (!WriteStringToFile(pid_str, file)) {
                PLOG(ERROR) << "couldn't write " << pid_str << " to " << file;
            }
        }

        if (ioprio_class_ != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), ioprio_class_, ioprio_pri_)) {
                PLOG(ERROR) << "Failed to set pid " << getpid()
                            << " ioprio=" << ioprio_class_ << "," << ioprio_pri_;
            }
        }

        if (needs_console) {
            setsid();
            OpenConsole();
        } else {
            ZapStdio();
        }

        setpgid(0, getpid());

        // As requested, set our gid, supplemental gids, and uid.
        if (gid_) {
            if (setgid(gid_) != 0) {
                PLOG(ERROR) << "setgid failed";
                _exit(127);
            }
        }
        if (!supp_gids_.empty()) {
            if (setgroups(supp_gids_.size(), &supp_gids_[0]) != 0) {
                PLOG(ERROR) << "setgroups failed";
                _exit(127);
            }
        }
        if (uid_) {
            if (setuid(uid_) != 0) {
                PLOG(ERROR) << "setuid failed";
                _exit(127);
            }
        }
        if (!seclabel_.empty()) {
            if (setexeccon(seclabel_.c_str()) < 0) {
                PLOG(ERROR) << "cannot setexeccon('" << seclabel_ << "')";
                _exit(127);
            }
        }
        if (priority_ != 0) {
            if (setpriority(PRIO_PROCESS, 0, priority_) != 0) {
                PLOG(ERROR) << "setpriority failed";
                _exit(127);
            }
        }

        std::vector<std::string> expanded_args;
        std::vector<char*> strs;
        expanded_args.resize(args_.size());
        strs.push_back(const_cast<char*>(args_[0].c_str()));
        for (std::size_t i = 1; i < args_.size(); ++i) {
            if (!expand_props(args_[i], &expanded_args[i])) {
                LOG(ERROR) << args_[0] << ": cannot expand '" << args_[i] << "'";
                _exit(127);
            }
            strs.push_back(const_cast<char*>(expanded_args[i].c_str()));
        }
        strs.push_back(nullptr);

        if (execve(strs[0], (char**) &strs[0], (char**) ENV) < 0) {
            PLOG(ERROR) << "cannot execve('" << strs[0] << "')";
        }

        _exit(127);
    }

    if (pid < 0) {
        PLOG(ERROR) << "failed to fork for '" << name_ << "'";
        pid_ = 0;
        return false;
    }

    time_started_ = gettime();
    pid_ = pid;
    flags_ |= SVC_RUNNING;

    errno = -createProcessGroup(uid_, pid_);
    if (errno != 0) {
        PLOG(ERROR) << "createProcessGroup(" << uid_ << ", " << pid_ << ") failed for service '" << name_ << "'";
    }

    if ((flags_ & SVC_EXEC) != 0) {
        LOG(INFO) << android::base::StringPrintf("SVC_EXEC pid %d (uid %d gid %d+%zu context %s) started; waiting...",
                                                 pid_, uid_, gid_, supp_gids_.size(),
                                                 !seclabel_.empty() ? seclabel_.c_str() : "default");
    }

    NotifyStateChange("running");
    return true;
}

bool Service::StartIfNotDisabled() {
    if (!(flags_ & SVC_DISABLED)) {
        return Start();
    } else {
        flags_ |= SVC_DISABLED_START;
    }
    return true;
}

bool Service::Enable() {
    flags_ &= ~(SVC_DISABLED | SVC_RC_DISABLED);
    if (flags_ & SVC_DISABLED_START) {
        return Start();
    }
    return true;
}

void Service::Reset() {
    StopOrReset(SVC_RESET);
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

void Service::Restart() {
    if (flags_ & SVC_RUNNING) {
        /* Stop, wait, then start the service. */
        StopOrReset(SVC_RESTART);
    } else if (!(flags_ & SVC_RESTARTING)) {
        /* Just start the service since it's not running. */
        Start();
    } /* else: Service is restarting anyways. */
}

void Service::RestartIfNeeded(time_t& process_needs_restart) {
    time_t next_start_time = time_started_ + 5;

    if (next_start_time <= gettime()) {
        flags_ &= (~SVC_RESTARTING);
        Start();
        return;
    }

    if ((next_start_time < process_needs_restart) ||
        (process_needs_restart == 0)) {
        process_needs_restart = next_start_time;
    }
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

void Service::PublishSocket(const std::string& name, int fd) const {
    std::string key = StringPrintf(ANDROID_SOCKET_ENV_PREFIX "%s", name.c_str());
    std::string val = StringPrintf("%d", fd);
    add_environment(key.c_str(), val.c_str());

    /* make sure we don't close-on-exec */
    fcntl(fd, F_SETFD, 0);
}

int ServiceManager::exec_count_ = 0;

ServiceManager::ServiceManager() {
}

ServiceManager& ServiceManager::GetInstance() {
    static ServiceManager instance;
    return instance;
}

void ServiceManager::AddService(std::unique_ptr<Service> service) {
    Service* old_service = FindServiceByName(service->name());
    if (old_service) {
        LOG(ERROR) << "ignored duplicate definition of service '" << service->name() << "'";
        return;
    }
    services_.emplace_back(std::move(service));
}

Service* ServiceManager::MakeExecOneshotService(const std::vector<std::string>& args) {
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

    exec_count_++;
    std::string name = StringPrintf("exec %d (%s)", exec_count_, str_args[0].c_str());
    unsigned flags = SVC_EXEC | SVC_ONESHOT;
    unsigned namespace_flags = 0;

    std::string seclabel = "";
    if (command_arg > 2 && args[1] != "-") {
        seclabel = args[1];
    }
    uid_t uid = 0;
    if (command_arg > 3) {
        uid = decode_uid(args[2].c_str());
    }
    gid_t gid = 0;
    std::vector<gid_t> supp_gids;
    if (command_arg > 4) {
        gid = decode_uid(args[3].c_str());
        std::size_t nr_supp_gids = command_arg - 1 /* -- */ - 4 /* exec SECLABEL UID GID */;
        for (size_t i = 0; i < nr_supp_gids; ++i) {
            supp_gids.push_back(decode_uid(args[4 + i].c_str()));
        }
    }

    std::unique_ptr<Service> svc_p(new Service(name, "default", flags, uid, gid,
                                               supp_gids, namespace_flags,
                                               seclabel, str_args));
    if (!svc_p) {
        LOG(ERROR) << "Couldn't allocate service for exec of '" << str_args[0] << "'";
        return nullptr;
    }
    Service* svc = svc_p.get();
    services_.push_back(std::move(svc_p));

    return svc;
}

Service* ServiceManager::FindServiceByName(const std::string& name) const {
    auto svc = std::find_if(services_.begin(), services_.end(),
                            [&name] (const std::unique_ptr<Service>& s) {
                                return name == s->name();
                            });
    if (svc != services_.end()) {
        return svc->get();
    }
    return nullptr;
}

Service* ServiceManager::FindServiceByPid(pid_t pid) const {
    auto svc = std::find_if(services_.begin(), services_.end(),
                            [&pid] (const std::unique_ptr<Service>& s) {
                                return s->pid() == pid;
                            });
    if (svc != services_.end()) {
        return svc->get();
    }
    return nullptr;
}

Service* ServiceManager::FindServiceByKeychord(int keychord_id) const {
    auto svc = std::find_if(services_.begin(), services_.end(),
                            [&keychord_id] (const std::unique_ptr<Service>& s) {
                                return s->keychord_id() == keychord_id;
                            });

    if (svc != services_.end()) {
        return svc->get();
    }
    return nullptr;
}

void ServiceManager::ForEachService(std::function<void(Service*)> callback) const {
    for (const auto& s : services_) {
        callback(s.get());
    }
}

void ServiceManager::ForEachServiceInClass(const std::string& classname,
                                           void (*func)(Service* svc)) const {
    for (const auto& s : services_) {
        if (classname == s->classname()) {
            func(s.get());
        }
    }
}

void ServiceManager::ForEachServiceWithFlags(unsigned matchflags,
                                             void (*func)(Service* svc)) const {
    for (const auto& s : services_) {
        if (s->flags() & matchflags) {
            func(s.get());
        }
    }
}

void ServiceManager::RemoveService(const Service& svc) {
    auto svc_it = std::find_if(services_.begin(), services_.end(),
                               [&svc] (const std::unique_ptr<Service>& s) {
                                   return svc.name() == s->name();
                               });
    if (svc_it == services_.end()) {
        return;
    }

    services_.erase(svc_it);
}

void ServiceManager::DumpState() const {
    for (const auto& s : services_) {
        s->DumpState();
    }
}

bool ServiceManager::ReapOneProcess() {
    int status;
    pid_t pid = TEMP_FAILURE_RETRY(waitpid(-1, &status, WNOHANG));
    if (pid == 0) {
        return false;
    } else if (pid == -1) {
        PLOG(ERROR) << "waitpid failed";
        return false;
    }

    Service* svc = FindServiceByPid(pid);

    std::string name;
    if (svc) {
        name = android::base::StringPrintf("Service '%s' (pid %d)",
                                           svc->name().c_str(), pid);
    } else {
        name = android::base::StringPrintf("Untracked pid %d", pid);
    }

    if (WIFEXITED(status)) {
        LOG(VERBOSE) << name << " exited with status " << WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        LOG(VERBOSE) << name << " killed by signal " << WTERMSIG(status);
    } else if (WIFSTOPPED(status)) {
        LOG(VERBOSE) << name << " stopped by signal " << WSTOPSIG(status);
    } else {
        LOG(VERBOSE) << name << " state changed";
    }

    if (!svc) {
        return true;
    }

    if (svc->Reap()) {
        waiting_for_exec = false;
        RemoveService(*svc);
    }

    return true;
}

void ServiceManager::ReapAnyOutstandingChildren() {
    while (ReapOneProcess()) {
    }
}

bool ServiceParser::ParseSection(const std::vector<std::string>& args,
                                 std::string* err) {
    if (args.size() < 3) {
        *err = "services must have a name and a program";
        return false;
    }

    const std::string& name = args[1];
    if (!IsValidName(name)) {
        *err = StringPrintf("invalid service name '%s'", name.c_str());
        return false;
    }

    std::vector<std::string> str_args(args.begin() + 2, args.end());
    service_ = std::make_unique<Service>(name, "default", str_args);
    return true;
}

bool ServiceParser::ParseLineSection(const std::vector<std::string>& args,
                                     const std::string& filename, int line,
                                     std::string* err) const {
    return service_ ? service_->HandleLine(args, err) : false;
}

void ServiceParser::EndSection() {
    if (service_) {
        ServiceManager::GetInstance().AddService(std::move(service_));
    }
}

bool ServiceParser::IsValidName(const std::string& name) const {
    if (name.size() > 16) {
        return false;
    }
    for (const auto& c : name) {
        if (!isalnum(c) && (c != '_') && (c != '-')) {
            return false;
        }
    }
    return true;
}
