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
#include <sys/prctl.h>
#include <task_profiles.h>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/threads.h>

#include <cutils/android_filesystem_config.h>

#include <json/reader.h>
#include <json/value.h>

using android::base::GetThreadId;
using android::base::StringPrintf;
using android::base::unique_fd;
using android::base::WriteStringToFile;

#define TASK_PROFILE_DB_FILE "/etc/task_profiles.json"

bool ProfileAttribute::GetPathForTask(int tid, std::string* path) const {
    std::string subgroup;
    if (!controller_->GetTaskGroup(tid, &subgroup)) {
        return false;
    }

    if (path == nullptr) {
        return true;
    }

    if (subgroup.empty()) {
        *path = StringPrintf("%s/%s", controller_->path(), file_name_.c_str());
    } else {
        *path = StringPrintf("%s/%s/%s", controller_->path(), subgroup.c_str(), file_name_.c_str());
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

bool SetAttributeAction::ExecuteForProcess(uid_t, pid_t pid) const {
    return ExecuteForTask(pid);
}

bool SetAttributeAction::ExecuteForTask(int tid) const {
    std::string path;

    if (!attribute_->GetPathForTask(tid, &path)) {
        PLOG(ERROR) << "Failed to find cgroup for tid " << tid;
        return false;
    }

    if (!WriteStringToFile(value_, path)) {
        PLOG(ERROR) << "Failed to write '" << value_ << "' to " << path;
        return false;
    }

    return true;
}

bool SetCgroupAction::IsAppDependentPath(const std::string& path) {
    return path.find("<uid>", 0) != std::string::npos || path.find("<pid>", 0) != std::string::npos;
}

SetCgroupAction::SetCgroupAction(const CgroupController* c, const std::string& p)
    : controller_(c), path_(p) {
    // cache file descriptor only if path is app independent
    if (IsAppDependentPath(path_)) {
        // file descriptor is not cached
        fd_.reset(-2);
        return;
    }

    std::string tasks_path = c->GetTasksFilePath(p.c_str());

    if (access(tasks_path.c_str(), W_OK) != 0) {
        // file is not accessible
        fd_.reset(-1);
        return;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(tasks_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to cache fd '" << tasks_path << "'";
        fd_.reset(-1);
        return;
    }

    fd_ = std::move(fd);
}

bool SetCgroupAction::AddTidToCgroup(int tid, int fd) {
    if (tid <= 0) {
        return true;
    }

    std::string value = std::to_string(tid);

    if (TEMP_FAILURE_RETRY(write(fd, value.c_str(), value.length())) < 0) {
        // If the thread is in the process of exiting, don't flag an error
        if (errno != ESRCH) {
            PLOG(ERROR) << "JoinGroup failed to write '" << value << "'; fd=" << fd;
            return false;
        }
    }

    return true;
}

bool SetCgroupAction::ExecuteForProcess(uid_t uid, pid_t pid) const {
    if (fd_ >= 0) {
        // fd is cached, reuse it
        if (!AddTidToCgroup(pid, fd_)) {
            PLOG(ERROR) << "Failed to add task into cgroup";
            return false;
        }
        return true;
    }

    if (fd_ == -1) {
        // no permissions to access the file, ignore
        return true;
    }

    // this is app-dependent path, file descriptor is not cached
    std::string procs_path = controller_->GetProcsFilePath(path_.c_str(), uid, pid);
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(open(procs_path.c_str(), O_WRONLY | O_CLOEXEC)));
    if (tmp_fd < 0) {
        PLOG(WARNING) << "Failed to open " << procs_path << ": " << strerror(errno);
        return false;
    }
    if (!AddTidToCgroup(pid, tmp_fd)) {
        PLOG(ERROR) << "Failed to add task into cgroup";
        return false;
    }

    return true;
}

bool SetCgroupAction::ExecuteForTask(int tid) const {
    if (fd_ >= 0) {
        // fd is cached, reuse it
        if (!AddTidToCgroup(tid, fd_)) {
            PLOG(ERROR) << "Failed to add task into cgroup";
            return false;
        }
        return true;
    }

    if (fd_ == -1) {
        // no permissions to access the file, ignore
        return true;
    }

    // application-dependent path can't be used with tid
    PLOG(ERROR) << "Application profile can't be applied to a thread";
    return false;
}

bool TaskProfile::ExecuteForProcess(uid_t uid, pid_t pid) const {
    for (const auto& element : elements_) {
        if (!element->ExecuteForProcess(uid, pid)) {
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
            return false;
        }
    }
    return true;
}

TaskProfiles& TaskProfiles::GetInstance() {
    static TaskProfiles instance;
    return instance;
}

TaskProfiles::TaskProfiles() {
    if (!Load(CgroupMap::GetInstance())) {
        LOG(ERROR) << "TaskProfiles::Load for [" << getpid() << "] failed";
    }
}

bool TaskProfiles::Load(const CgroupMap& cg_map) {
    std::string json_doc;

    if (!android::base::ReadFileToString(TASK_PROFILE_DB_FILE, &json_doc)) {
        LOG(ERROR) << "Failed to read task profiles from " << TASK_PROFILE_DB_FILE;
        return false;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse task profiles: " << reader.getFormattedErrorMessages();
        return false;
    }

    Json::Value attr = root["Attributes"];
    for (Json::Value::ArrayIndex i = 0; i < attr.size(); ++i) {
        std::string name = attr[i]["Name"].asString();
        std::string ctrlName = attr[i]["Controller"].asString();
        std::string file_name = attr[i]["File"].asString();

        if (attributes_.find(name) == attributes_.end()) {
            const CgroupController* controller = cg_map.FindController(ctrlName.c_str());
            if (controller) {
                attributes_[name] = std::make_unique<ProfileAttribute>(controller, file_name);
            } else {
                LOG(WARNING) << "Controller " << ctrlName << " is not found";
            }
        } else {
            LOG(WARNING) << "Attribute " << name << " is already defined";
        }
    }

    std::map<std::string, std::string> params;

    Json::Value profilesVal = root["Profiles"];
    for (Json::Value::ArrayIndex i = 0; i < profilesVal.size(); ++i) {
        Json::Value profileVal = profilesVal[i];

        std::string profileName = profileVal["Name"].asString();
        Json::Value actions = profileVal["Actions"];
        auto profile = std::make_unique<TaskProfile>();

        for (Json::Value::ArrayIndex actIdx = 0; actIdx < actions.size(); ++actIdx) {
            Json::Value actionVal = actions[actIdx];
            std::string actionName = actionVal["Name"].asString();
            Json::Value paramsVal = actionVal["Params"];
            if (actionName == "JoinCgroup") {
                std::string ctrlName = paramsVal["Controller"].asString();
                std::string path = paramsVal["Path"].asString();

                const CgroupController* controller = cg_map.FindController(ctrlName.c_str());
                if (controller) {
                    profile->Add(std::make_unique<SetCgroupAction>(controller, path));
                } else {
                    LOG(WARNING) << "JoinCgroup: controller " << ctrlName << " is not found";
                }
            } else if (actionName == "SetTimerSlack") {
                std::string slackValue = paramsVal["Slack"].asString();
                char* end;
                unsigned long slack;

                slack = strtoul(slackValue.c_str(), &end, 10);
                if (end > slackValue.c_str()) {
                    profile->Add(std::make_unique<SetTimerSlackAction>(slack));
                } else {
                    LOG(WARNING) << "SetTimerSlack: invalid parameter: " << slackValue;
                }
            } else if (actionName == "SetAttribute") {
                std::string attrName = paramsVal["Name"].asString();
                std::string attrValue = paramsVal["Value"].asString();

                auto iter = attributes_.find(attrName);
                if (iter != attributes_.end()) {
                    profile->Add(
                            std::make_unique<SetAttributeAction>(iter->second.get(), attrValue));
                } else {
                    LOG(WARNING) << "SetAttribute: unknown attribute: " << attrName;
                }
            } else if (actionName == "SetClamps") {
                std::string boostValue = paramsVal["Boost"].asString();
                std::string clampValue = paramsVal["Clamp"].asString();
                char* end;
                unsigned long boost;

                boost = strtoul(boostValue.c_str(), &end, 10);
                if (end > boostValue.c_str()) {
                    unsigned long clamp = strtoul(clampValue.c_str(), &end, 10);
                    if (end > clampValue.c_str()) {
                        profile->Add(std::make_unique<SetClampsAction>(boost, clamp));
                    } else {
                        LOG(WARNING) << "SetClamps: invalid parameter " << clampValue;
                    }
                } else {
                    LOG(WARNING) << "SetClamps: invalid parameter: " << boostValue;
                }
            } else {
                LOG(WARNING) << "Unknown profile action: " << actionName;
            }
        }
        profiles_[profileName] = std::move(profile);
    }

    return true;
}

const TaskProfile* TaskProfiles::GetProfile(const std::string& name) const {
    auto iter = profiles_.find(name);

    if (iter != profiles_.end()) {
        return iter->second.get();
    }
    return nullptr;
}

const ProfileAttribute* TaskProfiles::GetAttribute(const std::string& name) const {
    auto iter = attributes_.find(name);

    if (iter != attributes_.end()) {
        return iter->second.get();
    }
    return nullptr;
}
