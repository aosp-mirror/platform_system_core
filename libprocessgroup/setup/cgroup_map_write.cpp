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
#include <android/cgrouprc.h>
#include <json/reader.h>
#include <json/value.h>
#include <processgroup/format/cgroup_file.h>
#include <processgroup/processgroup.h>
#include <processgroup/setup.h>

#include "cgroup_descriptor.h"

using android::base::GetBoolProperty;
using android::base::StringPrintf;
using android::base::unique_fd;

namespace android {
namespace cgrouprc {

static constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
static constexpr const char* CGROUPS_DESC_VENDOR_FILE = "/vendor/etc/cgroups.json";

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

    if (uid.empty()) {
        return true;
    }

    passwd* uid_pwd = getpwnam(uid.c_str());
    if (!uid_pwd) {
        PLOG(ERROR) << "Unable to decode UID for '" << uid << "'";
        return false;
    }

    uid_t pw_uid = uid_pwd->pw_uid;
    gid_t gr_gid = -1;
    if (!gid.empty()) {
        group* gid_pwd = getgrnam(gid.c_str());
        if (!gid_pwd) {
            PLOG(ERROR) << "Unable to decode GID for '" << gid << "'";
            return false;
        }
        gr_gid = gid_pwd->gr_gid;
    }

    if (lchown(path.c_str(), pw_uid, gr_gid) < 0) {
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

static bool ReadDescriptorsFromFile(const std::string& file_name,
                                    std::map<std::string, CgroupDescriptor>* descriptors) {
    std::vector<CgroupDescriptor> result;
    std::string json_doc;

    if (!android::base::ReadFileToString(file_name, &json_doc)) {
        PLOG(ERROR) << "Failed to read task profiles from " << file_name;
        return false;
    }

    Json::Reader reader;
    Json::Value root;
    if (!reader.parse(json_doc, root)) {
        LOG(ERROR) << "Failed to parse cgroups description: " << reader.getFormattedErrorMessages();
        return false;
    }

    if (root.isMember("Cgroups")) {
        const Json::Value& cgroups = root["Cgroups"];
        for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
            std::string name = cgroups[i]["Controller"].asString();
            auto iter = descriptors->find(name);
            if (iter == descriptors->end()) {
                descriptors->emplace(
                        name, CgroupDescriptor(
                                      1, name, cgroups[i]["Path"].asString(),
                                      std::strtoul(cgroups[i]["Mode"].asString().c_str(), 0, 8),
                                      cgroups[i]["UID"].asString(), cgroups[i]["GID"].asString()));
            } else {
                iter->second = CgroupDescriptor(
                        1, name, cgroups[i]["Path"].asString(),
                        std::strtoul(cgroups[i]["Mode"].asString().c_str(), 0, 8),
                        cgroups[i]["UID"].asString(), cgroups[i]["GID"].asString());
            }
        }
    }

    if (root.isMember("Cgroups2")) {
        const Json::Value& cgroups2 = root["Cgroups2"];
        auto iter = descriptors->find(CGROUPV2_CONTROLLER_NAME);
        if (iter == descriptors->end()) {
            descriptors->emplace(
                    CGROUPV2_CONTROLLER_NAME,
                    CgroupDescriptor(2, CGROUPV2_CONTROLLER_NAME, cgroups2["Path"].asString(),
                                     std::strtoul(cgroups2["Mode"].asString().c_str(), 0, 8),
                                     cgroups2["UID"].asString(), cgroups2["GID"].asString()));
        } else {
            iter->second =
                    CgroupDescriptor(2, CGROUPV2_CONTROLLER_NAME, cgroups2["Path"].asString(),
                                     std::strtoul(cgroups2["Mode"].asString().c_str(), 0, 8),
                                     cgroups2["UID"].asString(), cgroups2["GID"].asString());
        }
    }

    return true;
}

static bool ReadDescriptors(std::map<std::string, CgroupDescriptor>* descriptors) {
    // load system cgroup descriptors
    if (!ReadDescriptorsFromFile(CGROUPS_DESC_FILE, descriptors)) {
        return false;
    }

    // load vendor cgroup descriptors if the file exists
    if (!access(CGROUPS_DESC_VENDOR_FILE, F_OK) &&
        !ReadDescriptorsFromFile(CGROUPS_DESC_VENDOR_FILE, descriptors)) {
        return false;
    }

    return true;
}

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

static bool SetupCgroup(const CgroupDescriptor& descriptor) {
    const format::CgroupController* controller = descriptor.controller();

    // mkdir <path> [mode] [owner] [group]
    if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
        LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
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
    unique_fd fd(TEMP_FAILURE_RETRY(open(CGROUPS_RC_PATH, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
                                         S_IRUSR | S_IRGRP | S_IROTH)));
    if (fd < 0) {
        PLOG(ERROR) << "open() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    format::CgroupFile fl;
    fl.version_ = format::CgroupFile::FILE_CURR_VERSION;
    fl.controller_count_ = descriptors.size();
    int ret = TEMP_FAILURE_RETRY(write(fd, &fl, sizeof(fl)));
    if (ret < 0) {
        PLOG(ERROR) << "write() failed for " << CGROUPS_RC_PATH;
        return false;
    }

    for (const auto& [name, descriptor] : descriptors) {
        ret = TEMP_FAILURE_RETRY(
                write(fd, descriptor.controller(), sizeof(format::CgroupController)));
        if (ret < 0) {
            PLOG(ERROR) << "write() failed for " << CGROUPS_RC_PATH;
            return false;
        }
    }

    return true;
}

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid)
    : controller_(version, 0, name, path), mode_(mode), uid_(uid), gid_(gid) {}

void CgroupDescriptor::set_mounted(bool mounted) {
    uint32_t flags = controller_.flags();
    if (mounted) {
        flags |= CGROUPRC_CONTROLLER_FLAG_MOUNTED;
    } else {
        flags &= ~CGROUPRC_CONTROLLER_FLAG_MOUNTED;
    }
    controller_.set_flags(flags);
}

}  // namespace cgrouprc
}  // namespace android

bool CgroupSetup() {
    using namespace android::cgrouprc;

    std::map<std::string, CgroupDescriptor> descriptors;

    if (getpid() != 1) {
        LOG(ERROR) << "Cgroup setup can be done only by init process";
        return false;
    }

    // Make sure we do this only one time. No need for std::call_once because
    // init is a single-threaded process
    if (access(CGROUPS_RC_PATH, F_OK) == 0) {
        LOG(WARNING) << "Attempt to call SetupCgroups more than once";
        return true;
    }

    // load cgroups.json file
    if (!ReadDescriptors(&descriptors)) {
        LOG(ERROR) << "Failed to load cgroup description file";
        return false;
    }

    // setup cgroups
    for (auto& [name, descriptor] : descriptors) {
        if (SetupCgroup(descriptor)) {
            descriptor.set_mounted(true);
        } else {
            // issue a warning and proceed with the next cgroup
            LOG(WARNING) << "Failed to setup " << name << " cgroup";
        }
    }

    // mkdir <CGROUPS_RC_DIR> 0711 system system
    if (!Mkdir(android::base::Dirname(CGROUPS_RC_PATH), 0711, "system", "system")) {
        LOG(ERROR) << "Failed to create directory for " << CGROUPS_RC_PATH << " file";
        return false;
    }

    // Generate <CGROUPS_RC_FILE> file which can be directly mmapped into
    // process memory. This optimizes performance, memory usage
    // and limits infrormation shared with unprivileged processes
    // to the minimum subset of information from cgroups.json
    if (!WriteRcFile(descriptors)) {
        LOG(ERROR) << "Failed to write " << CGROUPS_RC_PATH << " file";
        return false;
    }

    // chmod 0644 <CGROUPS_RC_PATH>
    if (fchmodat(AT_FDCWD, CGROUPS_RC_PATH, 0644, AT_SYMLINK_NOFOLLOW) < 0) {
        PLOG(ERROR) << "fchmodat() failed";
        return false;
    }

    return true;
}
