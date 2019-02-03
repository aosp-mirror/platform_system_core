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

static constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";

static constexpr const char* CGROUP_PROCS_FILE = "/cgroup.procs";
static constexpr const char* CGROUP_TASKS_FILE = "/tasks";
static constexpr const char* CGROUP_TASKS_FILE_V2 = "/cgroup.tasks";

static bool Mkdir(const std::string& path, mode_t mode, const std::string& uid,
                  const std::string& gid) {
    if (mode == 0) {
        mode = 0755;
    }

    if (mkdir(path.c_str(), mode) != 0) {
        /* chmod in case the directory already exists */
        if (errno == EEXIST) {
            if (fchmodat(AT_FDCWD, path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0) {
                // /acct is a special case when the directory already exists
                // TODO: check if file mode is already what we want instead of using EROFS
                if (errno != EROFS) {
                    PLOG(ERROR) << "fchmodat() failed for " << path;
                    return false;
                }
            }
        } else {
            PLOG(ERROR) << "mkdir() failed for " << path;
            return false;
        }
    }

    passwd* uid_pwd = nullptr;
    passwd* gid_pwd = nullptr;

    if (!uid.empty()) {
        uid_pwd = getpwnam(uid.c_str());
        if (!uid_pwd) {
            PLOG(ERROR) << "Unable to decode UID for '" << uid << "'";
            return false;
        }

        if (!gid.empty()) {
            gid_pwd = getpwnam(gid.c_str());
            if (!gid_pwd) {
                PLOG(ERROR) << "Unable to decode GID for '" << gid << "'";
                return false;
            }
        }
    }

    if (uid_pwd && lchown(path.c_str(), uid_pwd->pw_uid, gid_pwd ? gid_pwd->pw_uid : -1) < 0) {
        PLOG(ERROR) << "lchown() failed for " << path;
        return false;
    }

    /* chown may have cleared S_ISUID and S_ISGID, chmod again */
    if (mode & (S_ISUID | S_ISGID)) {
        if (fchmodat(AT_FDCWD, path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0) {
            PLOG(ERROR) << "fchmodat() failed for " << path;
            return false;
        }
    }

    return true;
}

static bool ReadDescriptors(std::map<std::string, CgroupDescriptor>* descriptors) {
    std::vector<CgroupDescriptor> result;
    std::string json_doc;

    if (!android::base::ReadFileToString(CGROUPS_DESC_FILE, &json_doc)) {
        LOG(ERROR) << "Failed to read task profiles from " << CGROUPS_DESC_FILE;
        return false;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse cgroups description: " << reader.getFormattedErrorMessages();
        return false;
    }

    Json::Value cgroups = root["Cgroups"];
    for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
        std::string name = cgroups[i]["Controller"].asString();
        descriptors->emplace(std::make_pair(
                name,
                CgroupDescriptor(1, name, cgroups[i]["Path"].asString(), cgroups[i]["Mode"].asInt(),
                                 cgroups[i]["UID"].asString(), cgroups[i]["GID"].asString())));
    }

    Json::Value cgroups2 = root["Cgroups2"];
    descriptors->emplace(std::make_pair(
            CGROUPV2_CONTROLLER_NAME,
            CgroupDescriptor(2, CGROUPV2_CONTROLLER_NAME, cgroups2["Path"].asString(),
                             cgroups2["Mode"].asInt(), cgroups2["UID"].asString(),
                             cgroups2["GID"].asString())));

    return true;
}

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

static bool SetupCgroup(const CgroupDescriptor& descriptor) {
    const CgroupController* controller = descriptor.controller();

    // mkdir <path> [mode] [owner] [group]
    if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
        PLOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
        return false;
    }

    int result;
    if (controller->version() == 2) {
        result = mount("none", controller->path(), "cgroup2", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                       nullptr);
    } else {
        // Unfortunately historically cpuset controller was mounted using a mount command
        // different from all other controllers. This results in controller attributes not
        // to be prepended with controller name. For example this way instead of
        // /dev/cpuset/cpuset.cpus the attribute becomes /dev/cpuset/cpus which is what
        // the system currently expects.
        if (!strcmp(controller->name(), "cpuset")) {
            // mount cpuset none /dev/cpuset nodev noexec nosuid
            result = mount("none", controller->path(), controller->name(),
                           MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr);
        } else {
            // mount cgroup none <path> nodev noexec nosuid <controller>
            result = mount("none", controller->path(), "cgroup", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                           controller->name());
        }
    }

    if (result < 0) {
        PLOG(ERROR) << "Failed to mount " << controller->name() << " cgroup";
        return false;
    }

    return true;
}

#else

// Stubs for non-Android targets.
static bool SetupCgroup(const CgroupDescriptor&) {
    return false;
}

#endif

static bool WriteRcFile(const std::map<std::string, CgroupDescriptor>& descriptors) {
    std::string cgroup_rc_path = StringPrintf("%s/%s", CGROUPS_RC_DIR, CgroupMap::CGROUPS_RC_FILE);
    unique_fd fd(TEMP_FAILURE_RETRY(open(cgroup_rc_path.c_str(),
                                         O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
                                         S_IRUSR | S_IRGRP | S_IROTH)));
    if (fd < 0) {
        PLOG(ERROR) << "open() failed for " << cgroup_rc_path;
        return false;
    }

    CgroupFile fl;
    fl.version_ = CgroupFile::FILE_CURR_VERSION;
    fl.controller_count_ = descriptors.size();
    int ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
    if (ret < 0) {
        PLOG(ERROR) << "write() failed for " << cgroup_rc_path;
        return false;
    }

    for (const auto& [name, descriptor] : descriptors) {
        ret = TEMP_FAILURE_RETRY(write(fd, descriptor.controller(), sizeof(CgroupController)));
        if (ret < 0) {
            PLOG(ERROR) << "write() failed for " << cgroup_rc_path;
            return false;
        }
    }

    return true;
}

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
        LOG(ERROR) << "Failed to read " << file_name;
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

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid)
    : controller_(version, name, path), mode_(mode), uid_(uid), gid_(gid) {}

CgroupMap::CgroupMap() : cg_file_data_(nullptr), cg_file_size_(0) {
    if (!LoadRcFile()) {
        PLOG(ERROR) << "CgroupMap::LoadRcFile called for [" << getpid() << "] failed";
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
    static CgroupMap instance;
    return instance;
}

bool CgroupMap::LoadRcFile() {
    struct stat sb;

    if (cg_file_data_) {
        // Data already initialized
        return true;
    }

    std::string cgroup_rc_path = StringPrintf("%s/%s", CGROUPS_RC_DIR, CGROUPS_RC_FILE);
    unique_fd fd(TEMP_FAILURE_RETRY(open(cgroup_rc_path.c_str(), O_RDONLY | O_CLOEXEC)));
    if (fd < 0) {
        PLOG(ERROR) << "open() failed for " << cgroup_rc_path;
        return false;
    }

    if (fstat(fd, &sb) < 0) {
        PLOG(ERROR) << "fstat() failed for " << cgroup_rc_path;
        return false;
    }

    cg_file_size_ = sb.st_size;
    if (cg_file_size_ < sizeof(CgroupFile)) {
        PLOG(ERROR) << "Invalid file format " << cgroup_rc_path;
        return false;
    }

    cg_file_data_ = (CgroupFile*)mmap(nullptr, cg_file_size_, PROT_READ, MAP_SHARED, fd, 0);
    if (cg_file_data_ == MAP_FAILED) {
        PLOG(ERROR) << "Failed to mmap " << cgroup_rc_path;
        return false;
    }

    if (cg_file_data_->version_ != CgroupFile::FILE_CURR_VERSION) {
        PLOG(ERROR) << cgroup_rc_path << " file version mismatch";
        return false;
    }

    return true;
}

void CgroupMap::Print() {
    LOG(INFO) << "File version = " << cg_file_data_->version_;
    LOG(INFO) << "File controller count = " << cg_file_data_->controller_count_;

    LOG(INFO) << "Mounted cgroups:";
    CgroupController* controller = (CgroupController*)(cg_file_data_ + 1);
    for (int i = 0; i < cg_file_data_->controller_count_; i++, controller++) {
        LOG(INFO) << "\t" << controller->name() << " ver " << controller->version() << " path "
                  << controller->path();
    }
}

bool CgroupMap::SetupCgroups() {
    std::map<std::string, CgroupDescriptor> descriptors;

    // load cgroups.json file
    if (!ReadDescriptors(&descriptors)) {
        PLOG(ERROR) << "Failed to load cgroup description file";
        return false;
    }

    // setup cgroups
    for (const auto& [name, descriptor] : descriptors) {
        if (!SetupCgroup(descriptor)) {
            // issue a warning and proceed with the next cgroup
            // TODO: mark the descriptor as invalid and skip it in WriteRcFile()
            LOG(WARNING) << "Failed to setup " << name << " cgroup";
        }
    }

    // mkdir <CGROUPS_RC_DIR> 0711 system system
    if (!Mkdir(CGROUPS_RC_DIR, 0711, "system", "system")) {
        PLOG(ERROR) << "Failed to create directory for <CGROUPS_RC_FILE> file";
        return false;
    }

    // Generate <CGROUPS_RC_FILE> file which can be directly mmapped into
    // process memory. This optimizes performance, memory usage
    // and limits infrormation shared with unprivileged processes
    // to the minimum subset of information from cgroups.json
    if (!WriteRcFile(descriptors)) {
        LOG(ERROR) << "Failed to write " << CGROUPS_RC_FILE << " file";
        return false;
    }

    std::string cgroup_rc_path = StringPrintf("%s/%s", CGROUPS_RC_DIR, CGROUPS_RC_FILE);
    // chmod 0644 <cgroup_rc_path>
    if (fchmodat(AT_FDCWD, cgroup_rc_path.c_str(), 0644, AT_SYMLINK_NOFOLLOW) < 0) {
        LOG(ERROR) << "fchmodat() failed";
        return false;
    }

    return true;
}

const CgroupController* CgroupMap::FindController(const std::string& name) const {
    if (!cg_file_data_) {
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
