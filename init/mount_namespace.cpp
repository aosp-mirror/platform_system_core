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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>

#include "util.h"

namespace android {
namespace init {
namespace {

static constexpr const char* kLinkerMountPoint = "/bionic/bin/linker";
static constexpr const char* kBootstrapLinkerPath = "/system/bin/bootstrap/linker";
static constexpr const char* kRuntimeLinkerPath = "/apex/com.android.runtime/bin/linker";

static constexpr const char* kBionicLibsMountPointDir = "/bionic/lib/";
static constexpr const char* kBootstrapBionicLibsDir = "/system/lib/bootstrap/";
static constexpr const char* kRuntimeBionicLibsDir = "/apex/com.android.runtime/lib/bionic/";

static constexpr const char* kLinkerMountPoint64 = "/bionic/bin/linker64";
static constexpr const char* kBootstrapLinkerPath64 = "/system/bin/bootstrap/linker64";
static constexpr const char* kRuntimeLinkerPath64 = "/apex/com.android.runtime/bin/linker64";

static constexpr const char* kBionicLibsMountPointDir64 = "/bionic/lib64/";
static constexpr const char* kBootstrapBionicLibsDir64 = "/system/lib64/bootstrap/";
static constexpr const char* kRuntimeBionicLibsDir64 = "/apex/com.android.runtime/lib64/bionic/";

static const std::vector<std::string> kBionicLibFileNames = {"libc.so", "libm.so", "libdl.so"};

static bool BindMount(const std::string& source, const std::string& mount_point,
                      bool recursive = false) {
    unsigned long mountflags = MS_BIND;
    if (recursive) {
        mountflags |= MS_REC;
    }
    if (mount(source.c_str(), mount_point.c_str(), nullptr, mountflags, nullptr) == -1) {
        PLOG(ERROR) << "Could not bind-mount " << source << " to " << mount_point;
        return false;
    }
    return true;
}

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

static bool BindMountBionic(const std::string& linker_source, const std::string& lib_dir_source,
                            const std::string& linker_mount_point,
                            const std::string& lib_mount_dir) {
    if (access(linker_source.c_str(), F_OK) != 0) {
        PLOG(INFO) << linker_source << " does not exist. skipping mounting bionic there.";
        // This can happen for 64-bit bionic in 32-bit only device.
        // It is okay to skip mounting the 64-bit bionic.
        return true;
    }
    if (!BindMount(linker_source, linker_mount_point)) {
        return false;
    }
    if (!MakePrivate(linker_mount_point)) {
        return false;
    }
    for (const auto& libname : kBionicLibFileNames) {
        std::string mount_point = lib_mount_dir + libname;
        std::string source = lib_dir_source + libname;
        if (!BindMount(source, mount_point)) {
            return false;
        }
        if (!MakePrivate(mount_point)) {
            return false;
        }
    }
    return true;
}

static bool IsBionicUpdatable() {
    static bool result = android::base::GetBoolProperty("ro.apex.IsBionicUpdatable", false);
    return result;
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

    // Since different files (bootstrap or runtime APEX) should be mounted to
    // the same mount point paths (e.g. /bionic/bin/linker, /bionic/lib/libc.so,
    // etc.) across the two mount namespaces, we create a private mount point at
    // /bionic so that a mount event for the bootstrap bionic in the mount
    // namespace for pre-apexd processes is not propagated to the other mount
    // namespace for post-apexd process, and vice versa.
    //
    // Other mount points other than /bionic, however, are all still shared.
    if (!BindMount("/bionic", "/bionic", true /*recursive*/)) return false;
    if (!MakePrivate("/bionic")) return false;

    // Bind-mount bootstrap bionic.
    if (!BindMountBionic(kBootstrapLinkerPath, kBootstrapBionicLibsDir, kLinkerMountPoint,
                         kBionicLibsMountPointDir))
        return false;
    if (!BindMountBionic(kBootstrapLinkerPath64, kBootstrapBionicLibsDir64, kLinkerMountPoint64,
                         kBionicLibsMountPointDir64))
        return false;

    // /apex is also a private mountpoint to give different sets of APEXes for
    // the bootstrap and default mount namespaces. The processes running with
    // the bootstrap namespace get APEXes from the read-only partition.
    if (!(MakePrivate("/apex"))) return false;

    bootstrap_ns_fd.reset(OpenMountNamespace());
    bootstrap_ns_id = GetMountNamespaceId();

    // When bionic is updatable via the runtime APEX, we create separate mount
    // namespaces for processes that are started before and after the APEX is
    // activated by apexd. In the namespace for pre-apexd processes, the bionic
    // from the /system partition (that we call bootstrap bionic) is
    // bind-mounted. In the namespace for post-apexd processes, the bionic from
    // the runtime APEX is bind-mounted.
    bool success = true;
    if (IsBionicUpdatable() && !IsRecoveryMode()) {
        // Creating a new namespace by cloning, saving, and switching back to
        // the original namespace.
        if (unshare(CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Cannot create mount namespace";
            return false;
        }
        default_ns_fd.reset(OpenMountNamespace());
        default_ns_id = GetMountNamespaceId();

        // By this unmount, the bootstrap bionic are not mounted in the default
        // mount namespace.
        if (umount2("/bionic", MNT_DETACH) == -1) {
            PLOG(ERROR) << "Cannot unmount /bionic";
            // Don't return here. We have to switch back to the bootstrap
            // namespace.
            success = false;
        }

        if (setns(bootstrap_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Cannot switch back to bootstrap mount namespace";
            return false;
        }
    } else {
        // Otherwise, default == bootstrap
        default_ns_fd.reset(OpenMountNamespace());
        default_ns_id = GetMountNamespaceId();
    }

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

// TODO(jiyong): remove this when /system/lib/libc.so becomes
// a symlink to /apex/com.android.runtime/lib/bionic/libc.so
bool SetupRuntimeBionic() {
    if (IsRecoveryMode()) {
        // We don't have multiple namespaces in recovery mode
        return true;
    }
    // Bind-mount bionic from the runtime APEX since it is now available. Note
    // that in case of IsBionicUpdatable() == false, these mounts are over the
    // existing existing bind mounts for the bootstrap bionic, which effectively
    // becomes hidden.
    if (!BindMountBionic(kRuntimeLinkerPath, kRuntimeBionicLibsDir, kLinkerMountPoint,
                         kBionicLibsMountPointDir))
        return false;
    if (!BindMountBionic(kRuntimeLinkerPath64, kRuntimeBionicLibsDir64, kLinkerMountPoint64,
                         kBionicLibsMountPointDir64))
        return false;

    LOG(INFO) << "Runtime bionic is set up";
    return true;
}

bool SwitchToBootstrapMountNamespaceIfNeeded() {
    if (IsRecoveryMode()) {
        // we don't have multiple namespaces in recovery mode
        return true;
    }
    if (bootstrap_ns_id != GetMountNamespaceId() && bootstrap_ns_fd.get() != -1 &&
        IsBionicUpdatable()) {
        if (setns(bootstrap_ns_fd.get(), CLONE_NEWNS) == -1) {
            PLOG(ERROR) << "Failed to switch to bootstrap mount namespace.";
            return false;
        }
    }
    return true;
}

}  // namespace init
}  // namespace android
