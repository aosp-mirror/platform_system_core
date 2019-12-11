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

#include "mount_namespace.h"

#include <sys/mount.h>

#include <string>
#include <vector>

#include <ApexProperties.sysprop.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android-base/unique_fd.h>

#include "util.h"

namespace android {
namespace init {
namespace {

static bool MakeShared(const std::string& mount_point, bool recursive = false) {
    unsigned long mountflags = MS_SHARED;
    if (recursive) {
        mountflags |= MS_REC;
    }
    if (mount(nullptr, mount_point.c_str(), nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Failed to change propagation type to shared";
        return false;
    }
    return true;
}

static bool MakePrivate(const std::string& mount_point, bool recursive = false) {
    unsigned long mountflags = MS_PRIVATE;
    if (recursive) {
        mountflags |= MS_REC;
    }
    if (mount(nullptr, mount_point.c_str(), nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Failed to change propagation type to private";
        return false;
    }
    return true;
}

static int OpenMountNamespace() {
    int fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PLOG(ERROR) << "Cannot open fd for current mount namespace";
    }
    return fd;
}

static std::string GetMountNamespaceId() {
    std::string ret;
    if (!android::base::Readlink("/proc/self/ns/mnt", &ret)) {
        PLOG(ERROR) << "Failed to read namespace ID";
        return "";
    }
    return ret;
}

static bool IsApexUpdatable() {
    static bool updatable = android::sysprop::ApexProperties::updatable().value_or(false);
    return updatable;
}

static Result<void> MountDir(const std::string& path, const std::string& mount_path) {
    if (int ret = mkdir(mount_path.c_str(), 0755); ret != 0 && ret != EEXIST) {
        return ErrnoError() << "Could not create mount point " << mount_path;
    }
    if (mount(path.c_str(), mount_path.c_str(), nullptr, MS_BIND, nullptr) != 0) {
        return ErrnoError() << "Could not bind mount " << path << " to " << mount_path;
    }
    return {};
}

static Result<void> ActivateFlattenedApexesFrom(const std::string& from_dir,
                                                const std::string& to_dir) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(from_dir.c_str()), closedir);
    if (!dir) {
        return {};
    }
    dirent* entry;
    while ((entry = readdir(dir.get())) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        if (entry->d_type == DT_DIR) {
            const std::string apex_path = from_dir + "/" + entry->d_name;
            const std::string mount_path = to_dir + "/" + entry->d_name;
            if (auto result = MountDir(apex_path, mount_path); !result) {
                return result;
            }
        }
    }
    return {};
}

static bool ActivateFlattenedApexesIfPossible() {
    if (IsRecoveryMode() || IsApexUpdatable()) {
        return true;
    }

    const std::string kApexTop = "/apex";
    const std::vector<std::string> kBuiltinDirsForApexes = {
            "/system/apex",
            "/system_ext/apex",
            "/product/apex",
            "/vendor/apex",
    };

    for (const auto& dir : kBuiltinDirsForApexes) {
        if (auto result = ActivateFlattenedApexesFrom(dir, kApexTop); !result) {
            LOG(ERROR) << result.error();
            return false;
        }
    }
    // Special casing for the ART APEX
    constexpr const char kArtApexMountPath[] = "/apex/com.android.art";
    static const std::vector<std::string> kArtApexDirNames = {"com.android.art.release",
                                                              "com.android.art.debug"};
    bool success = false;
    for (const auto& name : kArtApexDirNames) {
        std::string path = kApexTop + "/" + name;
        if (access(path.c_str(), F_OK) == 0) {
            if (auto result = MountDir(path, kArtApexMountPath); !result) {
                LOG(ERROR) << result.error();
                return false;
            }
            success = true;
            break;
        }
    }
    if (!success) {
        PLOG(ERROR) << "Failed to bind mount the ART APEX to " << kArtApexMountPath;
    }
    return success;
}

static android::base::unique_fd bootstrap_ns_fd;
static android::base::unique_fd default_ns_fd;

static std::string bootstrap_ns_id;
static std::string default_ns_id;

}  // namespace

bool SetupMountNamespaces() {
    // Set the propagation type of / as shared so that any mounting event (e.g.
    // /data) is by default visible to all processes. When private mounting is
    // needed for /foo/bar, then we will make /foo/bar as a mount point (by
    // bind-mounting by to itself) and set the propagation type of the mount
    // point to private.
    if (!MakeShared("/", true /*recursive*/)) return false;

    // /apex is a private mountpoint to give different sets of APEXes for
    // the bootstrap and default mount namespaces. The processes running with
    // the bootstrap namespace get APEXes from the read-only partition.
    if (!(MakePrivate("/apex"))) return false;

    // /linkerconfig is a private mountpoint to give a different linker configuration
    // based on the mount namespace. Subdirectory will be bind-mounted based on current mount
    // namespace
    if (!(MakePrivate("/linkerconfig"))) return false;

    bootstrap_ns_fd.reset(OpenMountNamespace());
    bootstrap_ns_id = GetMountNamespaceId();

    // When APEXes are updatable (e.g. not-flattened), we create separate mount
    // namespaces for processes that are started before and after the APEX is
    // activated by apexd. In the namespace for pre-apexd processes, small
    // number of essential APEXes (e.g. com.android.runtime) are activated.
    // In the namespace for post-apexd processes, all APEXes are activated.
    bool success = true;
    if (IsApexUpdatable() && !IsRecoveryMode()) {
        // Creating a new namespace by cloning, saving, and switching back to
        // the original namespace.
        if (unshare(CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Cannot create mount namespace";
            return false;
        }
        default_ns_fd.reset(OpenMountNamespace());
        default_ns_id = GetMountNamespaceId();

        if (setns(bootstrap_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Cannot switch back to bootstrap mount namespace";
            return false;
        }
    } else {
        // Otherwise, default == bootstrap
        default_ns_fd.reset(OpenMountNamespace());
        default_ns_id = GetMountNamespaceId();
    }

    success &= ActivateFlattenedApexesIfPossible();

    LOG(INFO) << "SetupMountNamespaces done";
    return success;
}

bool SwitchToDefaultMountNamespace() {
    if (IsRecoveryMode()) {
        // we don't have multiple namespaces in recovery mode
        return true;
    }
    if (default_ns_id != GetMountNamespaceId()) {
        if (setns(default_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Failed to switch back to the default mount namespace.";
            return false;
        }
    }

    LOG(INFO) << "Switched to default mount namespace";
    return true;
}

bool SwitchToBootstrapMountNamespaceIfNeeded() {
    if (IsRecoveryMode()) {
        // we don't have multiple namespaces in recovery mode
        return true;
    }
    if (bootstrap_ns_id != GetMountNamespaceId() && bootstrap_ns_fd.get() != -1 &&
        IsApexUpdatable()) {
        if (setns(bootstrap_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Failed to switch to bootstrap mount namespace.";
            return false;
        }
    }
    return true;
}

}  // namespace init
}  // namespace android
