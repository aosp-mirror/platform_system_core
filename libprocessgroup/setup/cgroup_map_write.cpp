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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <optional>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <processgroup/cgroup_descriptor.h>
#include <processgroup/processgroup.h>
#include <processgroup/setup.h>
#include <processgroup/util.h>

#include "../build_flags.h"
#include "../internal.h"

static constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
static constexpr const char* CGROUPS_DESC_VENDOR_FILE = "/vendor/etc/cgroups.json";

static constexpr const char* TEMPLATE_CGROUPS_DESC_API_FILE = "/etc/task_profiles/cgroups_%u.json";

static bool ChangeDirModeAndOwner(const std::string& path, mode_t mode, const std::string& uid,
                                  const std::string& gid, bool permissive_mode = false) {
    uid_t pw_uid = -1;
    gid_t gr_gid = -1;

    if (!uid.empty()) {
        passwd* uid_pwd = getpwnam(uid.c_str());
        if (!uid_pwd) {
            PLOG(ERROR) << "Unable to decode UID for '" << uid << "'";
            return false;
        }

        pw_uid = uid_pwd->pw_uid;
        gr_gid = -1;

        if (!gid.empty()) {
            group* gid_pwd = getgrnam(gid.c_str());
            if (!gid_pwd) {
                PLOG(ERROR) << "Unable to decode GID for '" << gid << "'";
                return false;
            }
            gr_gid = gid_pwd->gr_gid;
        }
    }

    auto dir = std::unique_ptr<DIR, decltype(&closedir)>(opendir(path.c_str()), closedir);

    if (dir == NULL) {
        PLOG(ERROR) << "opendir failed for " << path;
        return false;
    }

    struct dirent* dir_entry;
    while ((dir_entry = readdir(dir.get()))) {
        if (!strcmp("..", dir_entry->d_name)) {
            continue;
        }

        std::string file_path = path + "/" + dir_entry->d_name;

        if (pw_uid != -1 && lchown(file_path.c_str(), pw_uid, gr_gid) < 0) {
            PLOG(ERROR) << "lchown() failed for " << file_path;
            return false;
        }

        if (fchmodat(AT_FDCWD, file_path.c_str(), mode, AT_SYMLINK_NOFOLLOW) != 0 &&
            (errno != EROFS || !permissive_mode)) {
            PLOG(ERROR) << "fchmodat() failed for " << path;
            return false;
        }
    }

    return true;
}

static bool Mkdir(const std::string& path, mode_t mode, const std::string& uid,
                  const std::string& gid) {
    bool permissive_mode = false;

    if (mode == 0) {
        /* Allow chmod to fail */
        permissive_mode = true;
        mode = 0755;
    }

    if (mkdir(path.c_str(), mode) != 0) {
        // /acct is a special case when the directory already exists
        if (errno != EEXIST) {
            PLOG(ERROR) << "mkdir() failed for " << path;
            return false;
        } else {
            permissive_mode = true;
        }
    }

    if (uid.empty() && permissive_mode) {
        return true;
    }

    if (!ChangeDirModeAndOwner(path, mode, uid, gid, permissive_mode)) {
        PLOG(ERROR) << "change of ownership or mode failed for " << path;
        return false;
    }

    return true;
}

// To avoid issues in sdk_mac build
#if defined(__ANDROID__)

static bool IsOptionalController(const CgroupController* controller) {
    return controller->flags() & CGROUPRC_CONTROLLER_FLAG_OPTIONAL;
}

static bool MountV2CgroupController(const CgroupDescriptor& descriptor) {
    const CgroupController* controller = descriptor.controller();

    // /sys/fs/cgroup is created by cgroup2 with specific selinux permissions,
    // try to create again in case the mount point is changed
    if (!Mkdir(controller->path(), 0, "", "")) {
        LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
        return false;
    }

    // The memory_recursiveprot mount option has been introduced by kernel commit
    // 8a931f801340 ("mm: memcontrol: recursive memory.low protection"; v5.7). Try first to
    // mount with that option enabled. If mounting fails because the kernel is too old,
    // retry without that mount option.
    if (mount("none", controller->path(), "cgroup2", MS_NODEV | MS_NOEXEC | MS_NOSUID,
              "memory_recursiveprot") < 0) {
        LOG(INFO) << "Mounting memcg with memory_recursiveprot failed. Retrying without.";
        if (mount("none", controller->path(), "cgroup2", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                  nullptr) < 0) {
            PLOG(ERROR) << "Failed to mount cgroup v2";
            return IsOptionalController(controller);
        }
    }

    // selinux permissions change after mounting, so it's ok to change mode and owner now
    if (!ChangeDirModeAndOwner(controller->path(), descriptor.mode(), descriptor.uid(),
                               descriptor.gid())) {
        PLOG(ERROR) << "Change of ownership or mode failed for controller " << controller->name();
        return IsOptionalController(controller);
    }

    return true;
}

static bool ActivateV2CgroupController(const CgroupDescriptor& descriptor) {
    const CgroupController* controller = descriptor.controller();

    if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
        LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
        return false;
    }

    if (controller->flags() & CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION &&
        controller->max_activation_depth() > 0) {
        std::string str = "+";
        str += controller->name();
        std::string path = controller->path();
        path += "/cgroup.subtree_control";

        if (!android::base::WriteStringToFile(str, path)) {
            if (IsOptionalController(controller)) {
                PLOG(INFO) << "Failed to activate optional controller " << controller->name()
                           << " at " << path;
                return true;
            }
            PLOG(ERROR) << "Failed to activate controller " << controller->name();
            return false;
        }
    }

    return true;
}

static bool MountV1CgroupController(const CgroupDescriptor& descriptor) {
    const CgroupController* controller = descriptor.controller();

    // mkdir <path> [mode] [owner] [group]
    if (!Mkdir(controller->path(), descriptor.mode(), descriptor.uid(), descriptor.gid())) {
        LOG(ERROR) << "Failed to create directory for " << controller->name() << " cgroup";
        return false;
    }

    // Unfortunately historically cpuset controller was mounted using a mount command
    // different from all other controllers. This results in controller attributes not
    // to be prepended with controller name. For example this way instead of
    // /dev/cpuset/cpuset.cpus the attribute becomes /dev/cpuset/cpus which is what
    // the system currently expects.
    int res;
    if (!strcmp(controller->name(), "cpuset")) {
        // mount cpuset none /dev/cpuset nodev noexec nosuid
        res = mount("none", controller->path(), controller->name(),
                    MS_NODEV | MS_NOEXEC | MS_NOSUID, nullptr);
    } else {
        // mount cgroup none <path> nodev noexec nosuid <controller>
        res = mount("none", controller->path(), "cgroup", MS_NODEV | MS_NOEXEC | MS_NOSUID,
                    controller->name());
    }
    if (res != 0) {
        if (IsOptionalController(controller)) {
            PLOG(INFO) << "Failed to mount optional controller " << controller->name();
            return true;
        }
        PLOG(ERROR) << "Failed to mount controller " << controller->name();
        return false;
    }
    return true;
}

static bool SetupCgroup(const CgroupDescriptor& descriptor) {
    const CgroupController* controller = descriptor.controller();

    if (controller->version() == 2) {
        if (!strcmp(controller->name(), CGROUPV2_HIERARCHY_NAME)) {
            return MountV2CgroupController(descriptor);
        } else {
            return ActivateV2CgroupController(descriptor);
        }
    } else {
        return MountV1CgroupController(descriptor);
    }
}

#else

// Stubs for non-Android targets.
static bool SetupCgroup(const CgroupDescriptor&) {
    return false;
}

#endif

CgroupDescriptor::CgroupDescriptor(uint32_t version, const std::string& name,
                                   const std::string& path, mode_t mode, const std::string& uid,
                                   const std::string& gid, uint32_t flags,
                                   uint32_t max_activation_depth)
    : controller_(version, flags, name, path, max_activation_depth),
      mode_(mode),
      uid_(uid),
      gid_(gid) {}

void CgroupDescriptor::set_mounted(bool mounted) {
    uint32_t flags = controller_.flags();
    if (mounted) {
        flags |= CGROUPRC_CONTROLLER_FLAG_MOUNTED;
    } else {
        flags &= ~CGROUPRC_CONTROLLER_FLAG_MOUNTED;
    }
    controller_.set_flags(flags);
}

static std::optional<bool> MGLRUDisabled() {
    const std::string file_name = "/sys/kernel/mm/lru_gen/enabled";
    std::string content;
    if (!android::base::ReadFileToString(file_name, &content)) {
        PLOG(ERROR) << "Failed to read MGLRU state from " << file_name;
        return {};
    }

    return content == "0x0000";
}

static std::optional<bool> MEMCGDisabled(const CgroupDescriptorMap& descriptors) {
    std::string cgroup_v2_root = CGROUP_V2_ROOT_DEFAULT;
    const auto it = descriptors.find(CGROUPV2_HIERARCHY_NAME);
    if (it == descriptors.end()) {
        LOG(WARNING) << "No Cgroups2 path found in cgroups.json. Vendor has modified Android, and "
                     << "kernel memory use will be higher than intended.";
    } else if (it->second.controller()->path() != cgroup_v2_root) {
        cgroup_v2_root = it->second.controller()->path();
    }

    const std::string file_name = cgroup_v2_root + "/cgroup.controllers";
    std::string content;
    if (!android::base::ReadFileToString(file_name, &content)) {
        PLOG(ERROR) << "Failed to read cgroup controllers from " << file_name;
        return {};
    }

    // If we've forced memcg to v2 and it's not available, then it could only have been disabled
    // on the kernel command line (GKI sets CONFIG_MEMCG).
    return content.find("memory") == std::string::npos;
}

static bool CreateV2SubHierarchy(const std::string& path, const CgroupDescriptorMap& descriptors) {
    const auto cgv2_iter = descriptors.find(CGROUPV2_HIERARCHY_NAME);
    if (cgv2_iter == descriptors.end()) return false;
    const CgroupDescriptor cgv2_descriptor = cgv2_iter->second;

    if (!Mkdir(path, cgv2_descriptor.mode(), cgv2_descriptor.uid(), cgv2_descriptor.gid())) {
        PLOG(ERROR) << "Failed to create directory for " << path;
        return false;
    }

    // Activate all v2 controllers in path so they can be activated in
    // children as they are created.
    for (const auto& [name, descriptor] : descriptors) {
        const CgroupController* controller = descriptor.controller();
        std::uint32_t flags = controller->flags();
        std::uint32_t max_activation_depth = controller->max_activation_depth();
        const int depth = GetCgroupDepth(controller->path(), path);

        if (controller->version() == 2 && name != CGROUPV2_HIERARCHY_NAME &&
            flags & CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION && depth < max_activation_depth) {
            std::string str("+");
            str += controller->name();
            if (!android::base::WriteStringToFile(str, path + "/cgroup.subtree_control")) {
                if (flags & CGROUPRC_CONTROLLER_FLAG_OPTIONAL) {
                    PLOG(WARNING) << "Activation of cgroup controller " << str << " failed in path "
                                  << path;
                } else {
                    return false;
                }
            }
        }
    }
    return true;
}

bool CgroupSetup() {
    CgroupDescriptorMap descriptors;

    if (getpid() != 1) {
        LOG(ERROR) << "Cgroup setup can be done only by init process";
        return false;
    }

    // load cgroups.json file
    if (!ReadDescriptors(&descriptors)) {
        LOG(ERROR) << "Failed to load cgroup description file";
        return false;
    }

    // setup cgroups
    for (auto& [name, descriptor] : descriptors) {
        if (descriptor.controller()->flags() & CGROUPRC_CONTROLLER_FLAG_MOUNTED) {
            LOG(WARNING) << "Attempt to call CgroupSetup() more than once";
            return true;
        }

        if (!SetupCgroup(descriptor)) {
            // issue a warning and proceed with the next cgroup
            LOG(WARNING) << "Failed to setup " << name << " cgroup";
        }
    }

    if (android::libprocessgroup_flags::force_memcg_v2()) {
        if (MGLRUDisabled().value_or(false)) {
            LOG(WARNING) << "Memcg forced to v2 hierarchy with MGLRU disabled! "
                         << "Global reclaim performance will suffer.";
        }
        if (MEMCGDisabled(descriptors).value_or(false)) {
            LOG(WARNING) << "Memcg forced to v2 hierarchy while memcg is disabled by kernel "
                         << "command line!";
        }
    }

    // System / app isolation.
    // This really belongs in early-init in init.rc, but we cannot use the flag there.
    if (android::libprocessgroup_flags::cgroup_v2_sys_app_isolation()) {
        const auto it = descriptors.find(CGROUPV2_HIERARCHY_NAME);
        const std::string cgroup_v2_root = (it == descriptors.end())
                                                   ? CGROUP_V2_ROOT_DEFAULT
                                                   : it->second.controller()->path();

        LOG(INFO) << "Using system/app isolation under: " << cgroup_v2_root;
        if (!CreateV2SubHierarchy(cgroup_v2_root + "/apps", descriptors) ||
            !CreateV2SubHierarchy(cgroup_v2_root + "/system", descriptors)) {
            return false;
        }
    }

    return true;
}
