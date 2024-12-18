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

#include <errno.h>
#include <unistd.h>

#include <regex>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cgroup_map.h>
#include <processgroup/processgroup.h>
#include <processgroup/util.h>

using android::base::StringPrintf;
using android::base::WriteStringToFile;

static constexpr const char* CGROUP_PROCS_FILE = "/cgroup.procs";
static constexpr const char* CGROUP_TASKS_FILE = "/tasks";
static constexpr const char* CGROUP_TASKS_FILE_V2 = "/cgroup.threads";

uint32_t CgroupControllerWrapper::version() const {
    CHECK(HasValue());
    return controller_->version();
}

const char* CgroupControllerWrapper::name() const {
    CHECK(HasValue());
    return controller_->name();
}

const char* CgroupControllerWrapper::path() const {
    CHECK(HasValue());
    return controller_->path();
}

bool CgroupControllerWrapper::HasValue() const {
    return controller_ != nullptr;
}

bool CgroupControllerWrapper::IsUsable() {
    if (!HasValue()) return false;

    if (state_ == UNKNOWN) {
        if (__builtin_available(android 30, *)) {
            uint32_t flags = controller_->flags();
            state_ = (flags & CGROUPRC_CONTROLLER_FLAG_MOUNTED) != 0 ? USABLE : MISSING;
        } else {
            state_ = access(GetProcsFilePath("", 0, 0).c_str(), F_OK) == 0 ? USABLE : MISSING;
        }
    }

    return state_ == USABLE;
}

std::string CgroupControllerWrapper::GetTasksFilePath(const std::string& rel_path) const {
    std::string tasks_path = path();

    if (!rel_path.empty()) {
        tasks_path += "/" + rel_path;
    }
    return (version() == 1) ? tasks_path + CGROUP_TASKS_FILE : tasks_path + CGROUP_TASKS_FILE_V2;
}

std::string CgroupControllerWrapper::GetProcsFilePath(const std::string& rel_path, uid_t uid,
                                                      pid_t pid) const {
    std::string proc_path(path());
    proc_path.append("/").append(rel_path);
    proc_path = regex_replace(proc_path, std::regex("<uid>"), std::to_string(uid));
    proc_path = regex_replace(proc_path, std::regex("<pid>"), std::to_string(pid));

    return proc_path.append(CGROUP_PROCS_FILE);
}

bool CgroupControllerWrapper::GetTaskGroup(pid_t tid, std::string* group) const {
    std::string file_name = StringPrintf("/proc/%d/cgroup", tid);
    std::string content;
    if (!android::base::ReadFileToString(file_name, &content)) {
        PLOG(ERROR) << "Failed to read " << file_name;
        return false;
    }

    // if group is null and tid exists return early because
    // user is not interested in cgroup membership
    if (group == nullptr) {
        return true;
    }

    std::string cg_tag;

    if (version() == 2) {
        cg_tag = "0::";
    } else {
        cg_tag = StringPrintf(":%s:", name());
    }
    size_t start_pos = content.find(cg_tag);
    if (start_pos == std::string::npos) {
        return false;
    }

    start_pos += cg_tag.length() + 1;  // skip '/'
    size_t end_pos = content.find('\n', start_pos);
    if (end_pos == std::string::npos) {
        *group = content.substr(start_pos, std::string::npos);
    } else {
        *group = content.substr(start_pos, end_pos - start_pos);
    }

    return true;
}

CgroupMap::CgroupMap() {
    if (!LoadDescriptors()) {
        LOG(ERROR) << "CgroupMap::LoadDescriptors called for [" << getpid() << "] failed";
    }
}

CgroupMap& CgroupMap::GetInstance() {
    // Deliberately leak this object to avoid a race between destruction on
    // process exit and concurrent access from another thread.
    static auto* instance = new CgroupMap;
    return *instance;
}

bool CgroupMap::LoadDescriptors() {
    if (!loaded_) {
        loaded_ = ReadDescriptors(&descriptors_);
    }
    return loaded_;
}

void CgroupMap::Print() const {
    if (!loaded_) {
        LOG(ERROR) << "CgroupMap::Print called for [" << getpid()
                   << "] failed, cgroups were not initialized properly";
        return;
    }
    LOG(INFO) << "Controller count = " << descriptors_.size();

    LOG(INFO) << "Mounted cgroups:";

    for (const auto& [name, descriptor] : descriptors_) {
        LOG(INFO) << "\t" << descriptor.controller()->name() << " ver "
                  << descriptor.controller()->version() << " path "
                  << descriptor.controller()->path() << " flags "
                  << descriptor.controller()->flags();
    }
}

CgroupControllerWrapper CgroupMap::FindController(const std::string& name) const {
    if (!loaded_) {
        LOG(ERROR) << "CgroupMap::FindController called for [" << getpid()
                   << "] failed, cgroups were not initialized properly";
        return CgroupControllerWrapper(nullptr);
    }

    if (const auto it = descriptors_.find(name); it != descriptors_.end()) {
        return CgroupControllerWrapper(it->second.controller());
    }

    return CgroupControllerWrapper(nullptr);
}

CgroupControllerWrapper CgroupMap::FindControllerByPath(const std::string& path) const {
    if (!loaded_) {
        LOG(ERROR) << "CgroupMap::FindControllerByPath called for [" << getpid()
                   << "] failed, cgroups were not initialized properly";
        return CgroupControllerWrapper(nullptr);
    }

    for (const auto& [name, descriptor] : descriptors_) {
        if (path.starts_with(descriptor.controller()->path())) {
            return CgroupControllerWrapper(descriptor.controller());
        }
    }

    return CgroupControllerWrapper(nullptr);
}

bool CgroupMap::ActivateControllers(const std::string& path) const {
    return ::ActivateControllers(path, descriptors_);
}
