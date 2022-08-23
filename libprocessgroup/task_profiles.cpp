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

//#define LOG_NDEBUG 0
#define LOG_TAG "libprocessgroup"

#include <fcntl.h>
#include <task_profiles.h>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/threads.h>

#include <cutils/android_filesystem_config.h>

#include <json/reader.h>
#include <json/value.h>

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)
#include <sys/prctl.h>
#endif

using android::base::GetThreadId;
using android::base::GetUintProperty;
using android::base::StringPrintf;
using android::base::StringReplace;
using android::base::unique_fd;
using android::base::WriteStringToFile;

static constexpr const char* TASK_PROFILE_DB_FILE = "/etc/task_profiles.json";
static constexpr const char* TASK_PROFILE_DB_VENDOR_FILE = "/vendor/etc/task_profiles.json";

static constexpr const char* TEMPLATE_TASK_PROFILE_API_FILE =
        "/etc/task_profiles/task_profiles_%u.json";

class FdCacheHelper {
  public:
    enum FdState {
        FDS_INACCESSIBLE = -1,
        FDS_APP_DEPENDENT = -2,
        FDS_NOT_CACHED = -3,
    };

    static void Cache(const std::string& path, android::base::unique_fd& fd);
    static void Drop(android::base::unique_fd& fd);
    static void Init(const std::string& path, android::base::unique_fd& fd);
    static bool IsCached(const android::base::unique_fd& fd) { return fd > FDS_INACCESSIBLE; }

  private:
    static bool IsAppDependentPath(const std::string& path);
};

void FdCacheHelper::Init(const std::string& path, android::base::unique_fd& fd) {
    // file descriptors for app-dependent paths can't be cached
    if (IsAppDependentPath(path)) {
        // file descriptor is not cached
        fd.reset(FDS_APP_DEPENDENT);
        return;
    }
    // file descriptor can be cached later on request
    fd.reset(FDS_NOT_CACHED);
}

void FdCacheHelper::Cache(const std::string& path, android::base::unique_fd& fd) {
    if (fd != FDS_NOT_CACHED) {
        return;
    }

    if (access(path.c_str(), W_OK) != 0) {
        // file is not accessible
        fd.reset(FDS_INACCESSIBLE);
        return;
    }

    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (tmp_fd < 0) {
        PLOG(ERROR) << "Failed to cache fd '" << path << "'";
        fd.reset(FDS_INACCESSIBLE);
        return;
    }

    fd = std::move(tmp_fd);
}

void FdCacheHelper::Drop(android::base::unique_fd& fd) {
    if (fd == FDS_NOT_CACHED) {
        return;
    }

    fd.reset(FDS_NOT_CACHED);
}

bool FdCacheHelper::IsAppDependentPath(const std::string& path) {
    return path.find("<uid>", 0) != std::string::npos || path.find("<pid>", 0) != std::string::npos;
}

IProfileAttribute::~IProfileAttribute() = default;

void ProfileAttribute::Reset(const CgroupController& controller, const std::string& file_name) {
    controller_ = controller;
    file_name_ = file_name;
}

bool ProfileAttribute::GetPathForTask(int tid, std::string* path) const {
    std::string subgroup;
    if (!controller()->GetTaskGroup(tid, &subgroup)) {
        return false;
    }

    if (path == nullptr) {
        return true;
    }

    const std::string& file_name =
            controller()->version() == 2 && !file_v2_name_.empty() ? file_v2_name_ : file_name_;
    if (subgroup.empty()) {
        *path = StringPrintf("%s/%s", controller()->path(), file_name.c_str());
    } else {
        *path = StringPrintf("%s/%s/%s", controller()->path(), subgroup.c_str(), file_name.c_str());
    }
    return true;
}

bool SetClampsAction::ExecuteForProcess(uid_t, pid_t) const {
    // TODO: add support when kernel supports util_clamp
    LOG(WARNING) << "SetClampsAction::ExecuteForProcess is not supported";
    return false;
}

bool SetClampsAction::ExecuteForTask(int) const {
    // TODO: add support when kernel supports util_clamp
    LOG(WARNING) << "SetClampsAction::ExecuteForTask is not supported";
    return false;
}

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

bool SetTimerSlackAction::IsTimerSlackSupported(int tid) {
    auto file = StringPrintf("/proc/%d/timerslack_ns", tid);

    return (access(file.c_str(), W_OK) == 0);
}

bool SetTimerSlackAction::ExecuteForTask(int tid) const {
    static bool sys_supports_timerslack = IsTimerSlackSupported(tid);

    // v4.6+ kernels support the /proc/<tid>/timerslack_ns interface.
    // TODO: once we've backported this, log if the open(2) fails.
    if (sys_supports_timerslack) {
        auto file = StringPrintf("/proc/%d/timerslack_ns", tid);
        if (!WriteStringToFile(std::to_string(slack_), file)) {
            if (errno == ENOENT) {
                // This happens when process is already dead
                return true;
            }
            PLOG(ERROR) << "set_timerslack_ns write failed";
        }
    }

    // TODO: Remove when /proc/<tid>/timerslack_ns interface is backported.
    if (tid == 0 || tid == GetThreadId()) {
        if (prctl(PR_SET_TIMERSLACK, slack_) == -1) {
            PLOG(ERROR) << "set_timerslack_ns prctl failed";
        }
    }

    return true;
}

#else

bool SetTimerSlackAction::ExecuteForTask(int) const {
    return true;
};

#endif

bool SetAttributeAction::ExecuteForProcess(uid_t, pid_t pid) const {
    return ExecuteForTask(pid);
}

bool SetAttributeAction::ExecuteForTask(int tid) const {
    std::string path;

    if (!attribute_->GetPathForTask(tid, &path)) {
        LOG(ERROR) << "Failed to find cgroup for tid " << tid;
        return false;
    }

    if (!WriteStringToFile(value_, path)) {
        if (access(path.c_str(), F_OK) < 0) {
            if (optional_) {
                return true;
            } else {
                LOG(ERROR) << "No such cgroup attribute: " << path;
                return false;
            }
        }
        // The PLOG() statement below uses the error code stored in `errno` by
        // WriteStringToFile() because access() only overwrites `errno` if it fails
        // and because this code is only reached if the access() function returns 0.
        PLOG(ERROR) << "Failed to write '" << value_ << "' to " << path;
        return false;
    }

    return true;
}

SetCgroupAction::SetCgroupAction(const CgroupController& c, const std::string& p)
    : controller_(c), path_(p) {
    FdCacheHelper::Init(controller_.GetTasksFilePath(path_), fd_[ProfileAction::RCT_TASK]);
    // uid and pid don't matter because IsAppDependentPath ensures the path doesn't use them
    FdCacheHelper::Init(controller_.GetProcsFilePath(path_, 0, 0), fd_[ProfileAction::RCT_PROCESS]);
}

bool SetCgroupAction::AddTidToCgroup(int tid, int fd, const char* controller_name) {
    if (tid <= 0) {
        return true;
    }

    std::string value = std::to_string(tid);

    if (TEMP_FAILURE_RETRY(write(fd, value.c_str(), value.length())) == value.length()) {
        return true;
    }

    // If the thread is in the process of exiting, don't flag an error
    if (errno == ESRCH) {
        return true;
    }

    // ENOSPC is returned when cpuset cgroup that we are joining has no online cpus
    if (errno == ENOSPC && !strcmp(controller_name, "cpuset")) {
        // This is an abnormal case happening only in testing, so report it only once
        static bool empty_cpuset_reported = false;

        if (empty_cpuset_reported) {
            return true;
        }

        LOG(ERROR) << "Failed to add task '" << value
                   << "' into cpuset because all cpus in that cpuset are offline";
        empty_cpuset_reported = true;
    } else {
        PLOG(ERROR) << "AddTidToCgroup failed to write '" << value << "'; fd=" << fd;
    }

    return false;
}

ProfileAction::CacheUseResult SetCgroupAction::UseCachedFd(ResourceCacheType cache_type,
                                                           int id) const {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (FdCacheHelper::IsCached(fd_[cache_type])) {
        // fd is cached, reuse it
        if (!AddTidToCgroup(id, fd_[cache_type], controller()->name())) {
            LOG(ERROR) << "Failed to add task into cgroup";
            return ProfileAction::FAIL;
        }
        return ProfileAction::SUCCESS;
    }

    if (fd_[cache_type] == FdCacheHelper::FDS_INACCESSIBLE) {
        // no permissions to access the file, ignore
        return ProfileAction::SUCCESS;
    }

    if (cache_type == ResourceCacheType::RCT_TASK &&
        fd_[cache_type] == FdCacheHelper::FDS_APP_DEPENDENT) {
        // application-dependent path can't be used with tid
        PLOG(ERROR) << "Application profile can't be applied to a thread";
        return ProfileAction::FAIL;
    }

    return ProfileAction::UNUSED;
}

bool SetCgroupAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
    CacheUseResult result = UseCachedFd(ProfileAction::RCT_PROCESS, pid);
    if (result != ProfileAction::UNUSED) {
        return result == ProfileAction::SUCCESS;
    }

    // fd was not cached or cached fd can't be used
    std::string procs_path = controller()->GetProcsFilePath(path_, uid, pid);
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(procs_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (tmp_fd < 0) {
        PLOG(WARNING) << "Failed to open " << procs_path;
        return false;
    }
    if (!AddTidToCgroup(pid, tmp_fd, controller()->name())) {
        LOG(ERROR) << "Failed to add task into cgroup";
        return false;
    }

    return true;
}

bool SetCgroupAction::ExecuteForTask(int tid) const {
    CacheUseResult result = UseCachedFd(ProfileAction::RCT_TASK, tid);
    if (result != ProfileAction::UNUSED) {
        return result == ProfileAction::SUCCESS;
    }

    // fd was not cached or cached fd can't be used
    std::string tasks_path = controller()->GetTasksFilePath(path_);
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(tasks_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (tmp_fd < 0) {
        PLOG(WARNING) << "Failed to open " << tasks_path;
        return false;
    }
    if (!AddTidToCgroup(tid, tmp_fd, controller()->name())) {
        LOG(ERROR) << "Failed to add task into cgroup";
        return false;
    }

    return true;
}

void SetCgroupAction::EnableResourceCaching(ResourceCacheType cache_type) {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    // Return early to prevent unnecessary calls to controller_.Get{Tasks|Procs}FilePath() which
    // include regex evaluations
    if (fd_[cache_type] != FdCacheHelper::FDS_NOT_CACHED) {
        return;
    }
    switch (cache_type) {
        case (ProfileAction::RCT_TASK):
            FdCacheHelper::Cache(controller_.GetTasksFilePath(path_), fd_[cache_type]);
            break;
        case (ProfileAction::RCT_PROCESS):
            // uid and pid don't matter because IsAppDependentPath ensures the path doesn't use them
            FdCacheHelper::Cache(controller_.GetProcsFilePath(path_, 0, 0), fd_[cache_type]);
            break;
        default:
            LOG(ERROR) << "Invalid cache type is specified!";
            break;
    }
}

void SetCgroupAction::DropResourceCaching(ResourceCacheType cache_type) {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    FdCacheHelper::Drop(fd_[cache_type]);
}

WriteFileAction::WriteFileAction(const std::string& task_path, const std::string& proc_path,
                                 const std::string& value, bool logfailures)
    : task_path_(task_path), proc_path_(proc_path), value_(value), logfailures_(logfailures) {
    FdCacheHelper::Init(task_path_, fd_[ProfileAction::RCT_TASK]);
    if (!proc_path_.empty()) FdCacheHelper::Init(proc_path_, fd_[ProfileAction::RCT_PROCESS]);
}

bool WriteFileAction::WriteValueToFile(const std::string& value_, ResourceCacheType cache_type,
                                       int uid, int pid, bool logfailures) const {
    std::string value(value_);

    value = StringReplace(value, "<uid>", std::to_string(uid), true);
    value = StringReplace(value, "<pid>", std::to_string(pid), true);

    CacheUseResult result = UseCachedFd(cache_type, value);

    if (result != ProfileAction::UNUSED) {
        return result == ProfileAction::SUCCESS;
    }

    std::string path;
    if (cache_type == ProfileAction::RCT_TASK || proc_path_.empty()) {
        path = task_path_;
    } else {
        path = proc_path_;
    }

    // Use WriteStringToFd instead of WriteStringToFile because the latter will open file with
    // O_TRUNC which causes kernfs_mutex contention
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(path.c_str(), O_WRONLY | O_CLOEXEC)));

    if (tmp_fd < 0) {
        if (logfailures) PLOG(WARNING) << "Failed to open " << path;
        return false;
    }

    if (!WriteStringToFd(value, tmp_fd)) {
        if (logfailures) PLOG(ERROR) << "Failed to write '" << value << "' to " << path;
        return false;
    }

    return true;
}

ProfileAction::CacheUseResult WriteFileAction::UseCachedFd(ResourceCacheType cache_type,
                                                           const std::string& value) const {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (FdCacheHelper::IsCached(fd_[cache_type])) {
        // fd is cached, reuse it
        bool ret = WriteStringToFd(value, fd_[cache_type]);

        if (!ret && logfailures_) {
            if (cache_type == ProfileAction::RCT_TASK || proc_path_.empty()) {
                PLOG(ERROR) << "Failed to write '" << value << "' to " << task_path_;
            } else {
                PLOG(ERROR) << "Failed to write '" << value << "' to " << proc_path_;
            }
        }
        return ret ? ProfileAction::SUCCESS : ProfileAction::FAIL;
    }

    if (fd_[cache_type] == FdCacheHelper::FDS_INACCESSIBLE) {
        // no permissions to access the file, ignore
        return ProfileAction::SUCCESS;
    }

    if (cache_type == ResourceCacheType::RCT_TASK &&
        fd_[cache_type] == FdCacheHelper::FDS_APP_DEPENDENT) {
        // application-dependent path can't be used with tid
        PLOG(ERROR) << "Application profile can't be applied to a thread";
        return ProfileAction::FAIL;
    }
    return ProfileAction::UNUSED;
}

bool WriteFileAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
    if (!proc_path_.empty()) {
        return WriteValueToFile(value_, ProfileAction::RCT_PROCESS, uid, pid, logfailures_);
    }

    DIR* d;
    struct dirent* de;
    char proc_path[255];
    int t_pid;

    sprintf(proc_path, "/proc/%d/task", pid);
    if (!(d = opendir(proc_path))) {
        return false;
    }

    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') {
            continue;
        }

        t_pid = atoi(de->d_name);

        if (!t_pid) {
            continue;
        }

        WriteValueToFile(value_, ProfileAction::RCT_TASK, uid, t_pid, logfailures_);
    }

    closedir(d);

    return true;
}

bool WriteFileAction::ExecuteForTask(int tid) const {
    return WriteValueToFile(value_, ProfileAction::RCT_TASK, getuid(), tid, logfailures_);
}

void WriteFileAction::EnableResourceCaching(ResourceCacheType cache_type) {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    if (fd_[cache_type] != FdCacheHelper::FDS_NOT_CACHED) {
        return;
    }
    switch (cache_type) {
        case (ProfileAction::RCT_TASK):
            FdCacheHelper::Cache(task_path_, fd_[cache_type]);
            break;
        case (ProfileAction::RCT_PROCESS):
            if (!proc_path_.empty()) FdCacheHelper::Cache(proc_path_, fd_[cache_type]);
            break;
        default:
            LOG(ERROR) << "Invalid cache type is specified!";
            break;
    }
}

void WriteFileAction::DropResourceCaching(ResourceCacheType cache_type) {
    std::lock_guard<std::mutex> lock(fd_mutex_);
    FdCacheHelper::Drop(fd_[cache_type]);
}

bool ApplyProfileAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
    for (const auto& profile : profiles_) {
        profile->ExecuteForProcess(uid, pid);
    }
    return true;
}

bool ApplyProfileAction::ExecuteForTask(int tid) const {
    for (const auto& profile : profiles_) {
        profile->ExecuteForTask(tid);
    }
    return true;
}

void ApplyProfileAction::EnableResourceCaching(ResourceCacheType cache_type) {
    for (const auto& profile : profiles_) {
        profile->EnableResourceCaching(cache_type);
    }
}

void ApplyProfileAction::DropResourceCaching(ResourceCacheType cache_type) {
    for (const auto& profile : profiles_) {
        profile->DropResourceCaching(cache_type);
    }
}

void TaskProfile::MoveTo(TaskProfile* profile) {
    profile->elements_ = std::move(elements_);
    profile->res_cached_ = res_cached_;
}

bool TaskProfile::ExecuteForProcess(uid_t uid, pid_t pid) const {
    for (const auto& element : elements_) {
        if (!element->ExecuteForProcess(uid, pid)) {
            LOG(VERBOSE) << "Applying profile action " << element->Name() << " failed";
            return false;
        }
    }
    return true;
}

bool TaskProfile::ExecuteForTask(int tid) const {
    if (tid == 0) {
        tid = GetThreadId();
    }
    for (const auto& element : elements_) {
        if (!element->ExecuteForTask(tid)) {
            LOG(VERBOSE) << "Applying profile action " << element->Name() << " failed";
            return false;
        }
    }
    return true;
}

void TaskProfile::EnableResourceCaching(ProfileAction::ResourceCacheType cache_type) {
    if (res_cached_) {
        return;
    }

    for (auto& element : elements_) {
        element->EnableResourceCaching(cache_type);
    }

    res_cached_ = true;
}

void TaskProfile::DropResourceCaching(ProfileAction::ResourceCacheType cache_type) {
    if (!res_cached_) {
        return;
    }

    for (auto& element : elements_) {
        element->DropResourceCaching(cache_type);
    }

    res_cached_ = false;
}

void TaskProfiles::DropResourceCaching(ProfileAction::ResourceCacheType cache_type) const {
    for (auto& iter : profiles_) {
        iter.second->DropResourceCaching(cache_type);
    }
}

TaskProfiles& TaskProfiles::GetInstance() {
    // Deliberately leak this object to avoid a race between destruction on
    // process exit and concurrent access from another thread.
    static auto* instance = new TaskProfiles;
    return *instance;
}

TaskProfiles::TaskProfiles() {
    // load system task profiles
    if (!Load(CgroupMap::GetInstance(), TASK_PROFILE_DB_FILE)) {
        LOG(ERROR) << "Loading " << TASK_PROFILE_DB_FILE << " for [" << getpid() << "] failed";
    }

    // load API-level specific system task profiles if available
    unsigned int api_level = GetUintProperty<unsigned int>("ro.product.first_api_level", 0);
    if (api_level > 0) {
        std::string api_profiles_path =
                android::base::StringPrintf(TEMPLATE_TASK_PROFILE_API_FILE, api_level);
        if (!access(api_profiles_path.c_str(), F_OK) || errno != ENOENT) {
            if (!Load(CgroupMap::GetInstance(), api_profiles_path)) {
                LOG(ERROR) << "Loading " << api_profiles_path << " for [" << getpid() << "] failed";
            }
        }
    }

    // load vendor task profiles if the file exists
    if (!access(TASK_PROFILE_DB_VENDOR_FILE, F_OK) &&
        !Load(CgroupMap::GetInstance(), TASK_PROFILE_DB_VENDOR_FILE)) {
        LOG(ERROR) << "Loading " << TASK_PROFILE_DB_VENDOR_FILE << " for [" << getpid()
                   << "] failed";
    }
}

bool TaskProfiles::Load(const CgroupMap& cg_map, const std::string& file_name) {
    std::string json_doc;

    if (!android::base::ReadFileToString(file_name, &json_doc)) {
        LOG(ERROR) << "Failed to read task profiles from " << file_name;
        return false;
    }

    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value root;
    std::string errorMessage;
    if (!reader->parse(&*json_doc.begin(), &*json_doc.end(), &root, &errorMessage)) {
        LOG(ERROR) << "Failed to parse task profiles: " << errorMessage;
        return false;
    }

    const Json::Value& attr = root["Attributes"];
    for (Json::Value::ArrayIndex i = 0; i < attr.size(); ++i) {
        std::string name = attr[i]["Name"].asString();
        std::string controller_name = attr[i]["Controller"].asString();
        std::string file_attr = attr[i]["File"].asString();
        std::string file_v2_attr = attr[i]["FileV2"].asString();

        if (!file_v2_attr.empty() && file_attr.empty()) {
            LOG(ERROR) << "Attribute " << name << " has FileV2 but no File property";
            return false;
        }

        auto controller = cg_map.FindController(controller_name);
        if (controller.HasValue()) {
            auto iter = attributes_.find(name);
            if (iter == attributes_.end()) {
                attributes_[name] =
                        std::make_unique<ProfileAttribute>(controller, file_attr, file_v2_attr);
            } else {
                iter->second->Reset(controller, file_attr);
            }
        } else {
            LOG(WARNING) << "Controller " << controller_name << " is not found";
        }
    }

    const Json::Value& profiles_val = root["Profiles"];
    for (Json::Value::ArrayIndex i = 0; i < profiles_val.size(); ++i) {
        const Json::Value& profile_val = profiles_val[i];

        std::string profile_name = profile_val["Name"].asString();
        const Json::Value& actions = profile_val["Actions"];
        auto profile = std::make_shared<TaskProfile>(profile_name);

        for (Json::Value::ArrayIndex act_idx = 0; act_idx < actions.size(); ++act_idx) {
            const Json::Value& action_val = actions[act_idx];
            std::string action_name = action_val["Name"].asString();
            const Json::Value& params_val = action_val["Params"];
            if (action_name == "JoinCgroup") {
                std::string controller_name = params_val["Controller"].asString();
                std::string path = params_val["Path"].asString();

                auto controller = cg_map.FindController(controller_name);
                if (controller.HasValue()) {
                    profile->Add(std::make_unique<SetCgroupAction>(controller, path));
                } else {
                    LOG(WARNING) << "JoinCgroup: controller " << controller_name << " is not found";
                }
            } else if (action_name == "SetTimerSlack") {
                std::string slack_value = params_val["Slack"].asString();
                char* end;
                unsigned long slack;

                slack = strtoul(slack_value.c_str(), &end, 10);
                if (end > slack_value.c_str()) {
                    profile->Add(std::make_unique<SetTimerSlackAction>(slack));
                } else {
                    LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slack_value;
                }
            } else if (action_name == "SetAttribute") {
                std::string attr_name = params_val["Name"].asString();
                std::string attr_value = params_val["Value"].asString();
                bool optional = strcmp(params_val["Optional"].asString().c_str(), "true") == 0;

                auto iter = attributes_.find(attr_name);
                if (iter != attributes_.end()) {
                    profile->Add(std::make_unique<SetAttributeAction>(iter->second.get(),
                                                                      attr_value, optional));
                } else {
                    LOG(WARNING) << "SetAttribute: unknown attribute: " << attr_name;
                }
            } else if (action_name == "SetClamps") {
                std::string boost_value = params_val["Boost"].asString();
                std::string clamp_value = params_val["Clamp"].asString();
                char* end;
                unsigned long boost;

                boost = strtoul(boost_value.c_str(), &end, 10);
                if (end > boost_value.c_str()) {
                    unsigned long clamp = strtoul(clamp_value.c_str(), &end, 10);
                    if (end > clamp_value.c_str()) {
                        profile->Add(std::make_unique<SetClampsAction>(boost, clamp));
                    } else {
                        LOG(WARNING) << "SetClamps: invalid parameter " << clamp_value;
                    }
                } else {
                    LOG(WARNING) << "SetClamps: invalid parameter: " << boost_value;
                }
            } else if (action_name == "WriteFile") {
                std::string attr_filepath = params_val["FilePath"].asString();
                std::string attr_procfilepath = params_val["ProcFilePath"].asString();
                std::string attr_value = params_val["Value"].asString();
                // FilePath and Value are mandatory
                if (!attr_filepath.empty() && !attr_value.empty()) {
                    std::string attr_logfailures = params_val["LogFailures"].asString();
                    bool logfailures = attr_logfailures.empty() || attr_logfailures == "true";
                    profile->Add(std::make_unique<WriteFileAction>(attr_filepath, attr_procfilepath,
                                                                   attr_value, logfailures));
                } else if (attr_filepath.empty()) {
                    LOG(WARNING) << "WriteFile: invalid parameter: "
                                 << "empty filepath";
                } else if (attr_value.empty()) {
                    LOG(WARNING) << "WriteFile: invalid parameter: "
                                 << "empty value";
                }
            } else {
                LOG(WARNING) << "Unknown profile action: " << action_name;
            }
        }
        auto iter = profiles_.find(profile_name);
        if (iter == profiles_.end()) {
            profiles_[profile_name] = profile;
        } else {
            // Move the content rather that replace the profile because old profile might be
            // referenced from an aggregate profile if vendor overrides task profiles
            profile->MoveTo(iter->second.get());
            profile.reset();
        }
    }

    const Json::Value& aggregateprofiles_val = root["AggregateProfiles"];
    for (Json::Value::ArrayIndex i = 0; i < aggregateprofiles_val.size(); ++i) {
        const Json::Value& aggregateprofile_val = aggregateprofiles_val[i];

        std::string aggregateprofile_name = aggregateprofile_val["Name"].asString();
        const Json::Value& aggregateprofiles = aggregateprofile_val["Profiles"];
        std::vector<std::shared_ptr<TaskProfile>> profiles;
        bool ret = true;

        for (Json::Value::ArrayIndex pf_idx = 0; pf_idx < aggregateprofiles.size(); ++pf_idx) {
            std::string profile_name = aggregateprofiles[pf_idx].asString();

            if (profile_name == aggregateprofile_name) {
                LOG(WARNING) << "AggregateProfiles: recursive profile name: " << profile_name;
                ret = false;
                break;
            } else if (profiles_.find(profile_name) == profiles_.end()) {
                LOG(WARNING) << "AggregateProfiles: undefined profile name: " << profile_name;
                ret = false;
                break;
            } else {
                profiles.push_back(profiles_[profile_name]);
            }
        }
        if (ret) {
            auto profile = std::make_shared<TaskProfile>(aggregateprofile_name);
            profile->Add(std::make_unique<ApplyProfileAction>(profiles));
            profiles_[aggregateprofile_name] = profile;
        }
    }

    return true;
}

TaskProfile* TaskProfiles::GetProfile(std::string_view name) const {
    auto iter = profiles_.find(name);

    if (iter != profiles_.end()) {
        return iter->second.get();
    }
    return nullptr;
}

const IProfileAttribute* TaskProfiles::GetAttribute(std::string_view name) const {
    auto iter = attributes_.find(name);

    if (iter != attributes_.end()) {
        return iter->second.get();
    }
    return nullptr;
}

bool TaskProfiles::SetProcessProfiles(uid_t uid, pid_t pid,
                                      const std::vector<std::string>& profiles, bool use_fd_cache) {
    bool success = true;
    for (const auto& name : profiles) {
        TaskProfile* profile = GetProfile(name);
        if (profile != nullptr) {
            if (use_fd_cache) {
                profile->EnableResourceCaching(ProfileAction::RCT_PROCESS);
            }
            if (!profile->ExecuteForProcess(uid, pid)) {
                PLOG(WARNING) << "Failed to apply " << name << " process profile";
                success = false;
            }
        } else {
            PLOG(WARNING) << "Failed to find " << name << " process profile";
            success = false;
        }
    }
    return success;
}

bool TaskProfiles::SetTaskProfiles(int tid, const std::vector<std::string>& profiles,
                                   bool use_fd_cache) {
    bool success = true;
    for (const auto& name : profiles) {
        TaskProfile* profile = GetProfile(name);
        if (profile != nullptr) {
            if (use_fd_cache) {
                profile->EnableResourceCaching(ProfileAction::RCT_TASK);
            }
            if (!profile->ExecuteForTask(tid)) {
                PLOG(WARNING) << "Failed to apply " << name << " task profile";
                success = false;
            }
        } else {
            PLOG(WARNING) << "Failed to find " << name << " task profile";
            success = false;
        }
    }
    return success;
}
