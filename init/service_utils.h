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

#pragma once

#include <sys/resource.h>
#include <sys/types.h>

#include <optional>
#include <string>
#include <vector>

#include <android-base/unique_fd.h>
#include <cutils/iosched_policy.h>

#include "interprocess_fifo.h"
#include "mount_namespace.h"
#include "result.h"

namespace android {
namespace init {

// Constants used by Service::Start() for communication between parent and child.
enum ServiceCode : uint8_t {
    kActivatingCgroupsFailed,
    kCgroupsActivated,
    kSetSidFinished,
};

class Descriptor {
  public:
    Descriptor(const std::string& name, android::base::unique_fd fd)
        : name_(name), fd_(std::move(fd)){};

    // Publish() unsets FD_CLOEXEC from the FD and publishes its name via setenv().  It should be
    // called when starting a service after fork() and before exec().
    void Publish() const;

  private:
    std::string name_;
    android::base::unique_fd fd_;
};

struct SocketDescriptor {
    std::string name;
    int type = 0;
    uid_t uid = 0;
    gid_t gid = 0;
    int perm = 0;
    std::string context;
    bool passcred = false;
    bool listen = false;
    bool persist = false;

    // Create() creates the named unix domain socket in /dev/socket and returns a Descriptor object.
    // It should be called when starting a service, before calling fork(), such that the socket is
    // synchronously created before starting any other services, which may depend on it.
    Result<Descriptor> Create(const std::string& global_context) const;
};

struct FileDescriptor {
    std::string name;
    std::string type;

    Result<Descriptor> Create() const;
};

struct NamespaceInfo {
    int flags;
    // Pair of namespace type, path to name.
    std::vector<std::pair<int, std::string>> namespaces_to_enter;
};
Result<void> EnterNamespaces(const NamespaceInfo& info, const std::string& name,
                             std::optional<MountNamespace> override_mount_namespace);

struct ProcessAttributes {
    std::string console;
    IoSchedClass ioprio_class;
    int ioprio_pri;
    std::vector<std::pair<int, rlimit>> rlimits;
    uid_t uid;
    gid_t gid;
    std::vector<gid_t> supp_gids;
    int priority;
    bool stdio_to_kmsg;
};

inline bool RequiresConsole(const ProcessAttributes& attr) {
    return !attr.console.empty();
}

Result<void> SetProcessAttributes(const ProcessAttributes& attr, InterprocessFifo setsid_finished);

Result<void> WritePidToFiles(std::vector<std::string>* files);

}  // namespace init
}  // namespace android
