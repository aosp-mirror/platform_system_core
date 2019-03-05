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
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <regex>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/unique_fd.h>
#include <cgroup_map.h>
#include <json/reader.h>
#include <json/value.h>
#include <processgroup/processgroup.h>

using android::base::GetBoolProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

static constexpr const char* CGROUP_PROCS_FILE = "/cgroup.procs";
static constexpr const char* CGROUP_TASKS_FILE = "/tasks";
static constexpr const char* CGROUP_TASKS_FILE_V2 = "/cgroup.tasks";

CgroupController::CgroupController(uint32_t version, const std::string& name,
                                   const std::string& path) {
    version_ = version;
    strncpy(name_, name.c_str(), sizeof(name_) - 1);
    name_[sizeof(name_) - 1] = '\0';
    strncpy(path_, path.c_str(), sizeof(path_) - 1);
    path_[sizeof(path_) - 1] = '\0';
}

std::string CgroupController::GetTasksFilePath(const std::string& path) const {
    std::string tasks_path = path_;

    if (!path.empty()) {
        tasks_path += "/" + path;
    }
    return (version_ == 1) ? tasks_path + CGROUP_TASKS_FILE : tasks_path + CGROUP_TASKS_FILE_V2;
}

std::string CgroupController::GetProcsFilePath(const std::string& path, uid_t uid,
                                               pid_t pid) const {
    std::string proc_path(path_);
    proc_path.append("/").append(path);
    proc_path = regex_replace(proc_path, std::regex("<uid>"), std::to_string(uid));
    proc_path = regex_replace(proc_path, std::regex("<pid>"), std::to_string(pid));

    return proc_path.append(CGROUP_PROCS_FILE);
}

bool CgroupController::GetTaskGroup(int tid, std::string* group) const {
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

    std::string cg_tag = StringPrintf(":%s:", name_);
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

CgroupMap::CgroupMap() : cg_file_data_(nullptr), cg_file_size_(0) {
    if (!LoadRcFile()) {
        LOG(ERROR) << "CgroupMap::LoadRcFile called for [" << getpid() << "] failed";
    }
}

CgroupMap::~CgroupMap() {
    if (cg_file_data_) {
        munmap(cg_file_data_, cg_file_size_);
        cg_file_data_ = nullptr;
        cg_file_size_ = 0;
    }
}

CgroupMap& CgroupMap::GetInstance() {
    // Deliberately leak this object to avoid a race between destruction on
    // process exit and concurrent access from another thread.
    static auto* instance = new CgroupMap;
    return *instance;
}

bool CgroupMap::LoadRcFile() {
    struct stat sb;

    if (cg_file_data_) {
        // Data already initialized
        return true;
    }

    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_PATH, O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "open() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    if (fstat(fd, &sb) < 0) {
        PLOG(ERROR) << "fstat() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    size_t file_size = sb.st_size;
    if (file_size < sizeof(CgroupFile)) {
        LOG(ERROR) << "Invalid file format " << CGROUPS_RC_PATH;
        return false;
    }

    CgroupFile* file_data = (CgroupFile*)mmap(nullptr, file_size, PROT_READ, MAP_SHARED, fd, 0);
    if (file_data == MAP_FAILED) {
        PLOG(ERROR) << "Failed to mmap " << CGROUPS_RC_PATH;
        return false;
    }

    if (file_data->version_ != CgroupFile::FILE_CURR_VERSION) {
        LOG(ERROR) << CGROUPS_RC_PATH << " file version mismatch";
        munmap(file_data, file_size);
        return false;
    }

    if (file_size != sizeof(CgroupFile) + file_data->controller_count_ * sizeof(CgroupController)) {
        LOG(ERROR) << CGROUPS_RC_PATH << " file has invalid size";
        munmap(file_data, file_size);
        return false;
    }

    cg_file_data_ = file_data;
    cg_file_size_ = file_size;

    return true;
}

void CgroupMap::Print() const {
    if (!cg_file_data_) {
        LOG(ERROR) << "CgroupMap::Print called for [" << getpid()
                   << "] failed, RC file was not initialized properly";
        return;
    }
    LOG(INFO) << "File version = " << cg_file_data_->version_;
    LOG(INFO) << "File controller count = " << cg_file_data_->controller_count_;

    LOG(INFO) << "Mounted cgroups:";
    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        LOG(INFO) << "\t" << controller->name() << " ver " << controller->version() << " path "
                  << controller->path();
    }
}

const CgroupController* CgroupMap::FindController(const std::string& name) const {
    if (!cg_file_data_) {
        LOG(ERROR) << "CgroupMap::FindController called for [" << getpid()
                   << "] failed, RC file was not initialized properly";
        return nullptr;
    }

    // skip the file header to get to the first controller
    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        if (name == controller->name()) {
            return controller;
        }
    }

    return nullptr;
}
