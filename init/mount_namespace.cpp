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

#ifndef RECOVERY
#define ACTIVATE_FLATTENED_APEX 1
#endif

#ifdef ACTIVATE_FLATTENED_APEX
#include <apex_manifest.pb.h>
#include <com_android_apex.h>
#include <selinux/android.h>
#endif  // ACTIVATE_FLATTENED_APEX

namespace android {
namespace init {
namespace {

static bool BindMount(const std::string& source, const std::string& mount_point) {
    if (mount(source.c_str(), mount_point.c_str(), nullptr, MS_BIND | MS_REC, nullptr) == -1) {
        PLOG(ERROR) << "Failed to bind mount " << source;
        return false;
    }
    return true;
}

static bool ChangeMount(const std::string& mount_point, unsigned long mountflags) {
    if (mount(nullptr, mount_point.c_str(), nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Failed to remount " << mount_point << " as " << std::hex << mountflags;
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

#ifdef ACTIVATE_FLATTENED_APEX

static Result<void> MountDir(const std::string& path, const std::string& mount_path) {
    if (int ret = mkdir(mount_path.c_str(), 0755); ret != 0 && errno != EEXIST) {
        return ErrnoError() << "Could not create mount point " << mount_path;
    }
    if (mount(path.c_str(), mount_path.c_str(), nullptr, MS_BIND, nullptr) != 0) {
        return ErrnoError() << "Could not bind mount " << path << " to " << mount_path;
    }
    return {};
}

static Result<apex::proto::ApexManifest> GetApexManifest(const std::string& apex_dir) {
    const std::string manifest_path = apex_dir + "/apex_manifest.pb";
    std::string content;
    if (!android::base::ReadFileToString(manifest_path, &content)) {
        return Error() << "Failed to read manifest file: " << manifest_path;
    }
    apex::proto::ApexManifest manifest;
    if (!manifest.ParseFromString(content)) {
        return Error() << "Can't parse manifest file: " << manifest_path;
    }
    return manifest;
}

template <typename Fn>
static Result<void> ActivateFlattenedApexesFrom(const std::string& from_dir,
                                                const std::string& to_dir, Fn on_activate) {
    std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(from_dir.c_str()), closedir);
    if (!dir) {
        return {};
    }
    dirent* entry;
    std::vector<std::string> entries;

    while ((entry = readdir(dir.get())) != nullptr) {
        if (entry->d_name[0] == '.') continue;
        if (entry->d_type == DT_DIR) {
            entries.push_back(entry->d_name);
        }
    }

    std::sort(entries.begin(), entries.end());
    for (const auto& name : entries) {
        const std::string apex_path = from_dir + "/" + name;
        const auto apex_manifest = GetApexManifest(apex_path);
        if (!apex_manifest.ok()) {
            LOG(ERROR) << apex_path << " is not an APEX directory: " << apex_manifest.error();
            continue;
        }
        const std::string mount_path = to_dir + "/" + apex_manifest->name();
        if (auto result = MountDir(apex_path, mount_path); !result.ok()) {
            return result;
        }
        on_activate(apex_path, *apex_manifest);
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

    std::vector<com::android::apex::ApexInfo> apex_infos;
    auto on_activate = [&](const std::string& apex_path,
                           const apex::proto::ApexManifest& apex_manifest) {
        apex_infos.emplace_back(apex_manifest.name(), apex_path, apex_path, apex_manifest.version(),
                                apex_manifest.versionname(), /*isFactory=*/true, /*isActive=*/true);
    };

    for (const auto& dir : kBuiltinDirsForApexes) {
        if (auto result = ActivateFlattenedApexesFrom(dir, kApexTop, on_activate); !result.ok()) {
            LOG(ERROR) << result.error();
            return false;
        }
    }

    std::ostringstream oss;
    com::android::apex::ApexInfoList apex_info_list(apex_infos);
    com::android::apex::write(oss, apex_info_list);
    const std::string kApexInfoList = kApexTop + "/apex-info-list.xml";
    if (!android::base::WriteStringToFile(oss.str(), kApexInfoList)) {
        PLOG(ERROR) << "Failed to write " << kApexInfoList;
        return false;
    }
    if (selinux_android_restorecon(kApexInfoList.c_str(), 0) != 0) {
        PLOG(ERROR) << "selinux_android_restorecon(" << kApexInfoList << ") failed";
    }

    return true;
}

#endif  // ACTIVATE_FLATTENED_APEX

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
    if (!ChangeMount("/", MS_SHARED | MS_REC)) return false;

    // /apex is a private mountpoint to give different sets of APEXes for
    // the bootstrap and default mount namespaces. The processes running with
    // the bootstrap namespace get APEXes from the read-only partition.
    if (!(ChangeMount("/apex", MS_PRIVATE))) return false;

    // /linkerconfig is a private mountpoint to give a different linker configuration
    // based on the mount namespace. Subdirectory will be bind-mounted based on current mount
    // namespace
    if (!(ChangeMount("/linkerconfig", MS_PRIVATE))) return false;

    // The two mount namespaces present challenges for scoped storage, because
    // vold, which is responsible for most of the mounting, lives in the
    // bootstrap mount namespace, whereas most other daemons and all apps live
    // in the default namespace.  Scoped storage has a need for a
    // /mnt/installer view that is a slave bind mount of /mnt/user - in other
    // words, all mounts under /mnt/user should automatically show up under
    // /mnt/installer. However, additional mounts done under /mnt/installer
    // should not propagate back to /mnt/user. In a single mount namespace
    // this is easy to achieve, by simply marking the /mnt/installer a slave
    // bind mount. Unfortunately, if /mnt/installer is only created and
    // bind mounted after the two namespaces are created below, we end up
    // with the following situation:
    // /mnt/user and /mnt/installer share the same peer group in both the
    // bootstrap and default namespaces. Marking /mnt/installer slave in either
    // namespace means that it won't propagate events to the /mnt/installer in
    // the other namespace, which is still something we require - vold is the
    // one doing the mounting under /mnt/installer, and those mounts should
    // show up in the default namespace as well.
    //
    // The simplest solution is to do the bind mount before the two namespaces
    // are created: the effect is that in both namespaces, /mnt/installer is a
    // slave to the /mnt/user mount, and at the same time /mnt/installer in the
    // bootstrap namespace shares a peer group with /mnt/installer in the
    // default namespace.
    // /mnt/androidwritable is similar to /mnt/installer but serves for
    // MOUNT_EXTERNAL_ANDROID_WRITABLE apps.
    if (!mkdir_recursive("/mnt/user", 0755)) return false;
    if (!mkdir_recursive("/mnt/installer", 0755)) return false;
    if (!mkdir_recursive("/mnt/androidwritable", 0755)) return false;
    if (!(BindMount("/mnt/user", "/mnt/installer"))) return false;
    if (!(BindMount("/mnt/user", "/mnt/androidwritable"))) return false;
    // First, make /mnt/installer and /mnt/androidwritable a slave bind mount
    if (!(ChangeMount("/mnt/installer", MS_SLAVE))) return false;
    if (!(ChangeMount("/mnt/androidwritable", MS_SLAVE))) return false;
    // Then, make it shared again - effectively creating a new peer group, that
    // will be inherited by new mount namespaces.
    if (!(ChangeMount("/mnt/installer", MS_SHARED))) return false;
    if (!(ChangeMount("/mnt/androidwritable", MS_SHARED))) return false;

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
#ifdef ACTIVATE_FLATTENED_APEX
    success &= ActivateFlattenedApexesIfPossible();
#endif
    LOG(INFO) << "SetupMountNamespaces done";
    return success;
}

Result<void> SwitchToMountNamespaceIfNeeded(MountNamespace target_mount_namespace) {
    if (IsRecoveryMode() || !IsApexUpdatable()) {
        // we don't have multiple namespaces in recovery mode or if apex is not updatable
        return {};
    }
    const auto& ns_id = target_mount_namespace == NS_BOOTSTRAP ? bootstrap_ns_id : default_ns_id;
    const auto& ns_fd = target_mount_namespace == NS_BOOTSTRAP ? bootstrap_ns_fd : default_ns_fd;
    const auto& ns_name = target_mount_namespace == NS_BOOTSTRAP ? "bootstrap" : "default";
    if (ns_id != GetMountNamespaceId() && ns_fd.get() != -1) {
        if (setns(ns_fd.get(), CLONE_NEWNS) == -1) {
            return ErrnoError() << "Failed to switch to " << ns_name << " mount namespace.";
        }
    }
    return {};
}

base::Result<MountNamespace> GetCurrentMountNamespace() {
    std::string current_namespace_id = GetMountNamespaceId();
    if (current_namespace_id == "") {
        return Error() << "Failed to get current mount namespace ID";
    }

    if (current_namespace_id == bootstrap_ns_id) {
        return NS_BOOTSTRAP;
    } else if (current_namespace_id == default_ns_id) {
        return NS_DEFAULT;
    }

    return Error() << "Failed to find current mount namespace";
}

}  // namespace init
}  // namespace android
