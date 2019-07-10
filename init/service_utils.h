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

#include <string>
#include <vector>

#include <cutils/iosched_policy.h>

#include "result.h"

namespace android {
namespace init {

struct NamespaceInfo {
    int flags;
    // Pair of namespace type, path to name.
    std::vector<std::pair<int, std::string>> namespaces_to_enter;
};
Result<void> EnterNamespaces(const NamespaceInfo& info, const std::string& name, bool pre_apexd);

struct ProcessAttributes {
    std::string console;
    IoSchedClass ioprio_class;
    int ioprio_pri;
    std::vector<std::pair<int, rlimit>> rlimits;
    uid_t uid;
    gid_t gid;
    std::vector<gid_t> supp_gids;
    int priority;
};
Result<void> SetProcessAttributes(const ProcessAttributes& attr);

Result<void> WritePidToFiles(std::vector<std::string>* files);

}  // namespace init
}  // namespace android
