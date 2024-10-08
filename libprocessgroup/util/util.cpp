/*
 * Copyright (C) 2024 The Android Open Source Project
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

#include <processgroup/util.h>

#include <algorithm>
#include <iterator>
#include <optional>
#include <string_view>

#include <mntent.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <json/reader.h>
#include <json/value.h>

#include "../build_flags.h"
#include "../internal.h"

using android::base::GetUintProperty;

namespace {

constexpr const char* CGROUPS_DESC_FILE = "/etc/cgroups.json";
constexpr const char* CGROUPS_DESC_VENDOR_FILE = "/vendor/etc/cgroups.json";
constexpr const char* TEMPLATE_CGROUPS_DESC_API_FILE = "/etc/task_profiles/cgroups_%u.json";

// This should match the publicly declared value in processgroup.h,
// but we don't want this library to depend on libprocessgroup.
constexpr std::string CGROUPV2_HIERARCHY_NAME_INTERNAL = "cgroup2";

const char SEP = '/';

std::string DeduplicateAndTrimSeparators(const std::string& path) {
    bool lastWasSep = false;
    std::string ret;

    std::copy_if(path.begin(), path.end(), std::back_inserter(ret), [&lastWasSep](char c) {
        if (lastWasSep) {
            if (c == SEP) return false;
            lastWasSep = false;
        } else if (c == SEP) {
            lastWasSep = true;
        }
        return true;
    });

    if (ret.length() > 1 && ret.back() == SEP) ret.pop_back();

    return ret;
}

void MergeCgroupToDescriptors(CgroupDescriptorMap* descriptors, const Json::Value& cgroup,
                              const std::string& name, const std::string& root_path,
                              int cgroups_version) {
    const std::string cgroup_path = cgroup["Path"].asString();
    std::string path;

    if (!root_path.empty()) {
        path = root_path;
        if (cgroup_path != ".") {
            path += "/";
            path += cgroup_path;
        }
    } else {
        path = cgroup_path;
    }

    uint32_t controller_flags = 0;

    if (cgroup["NeedsActivation"].isBool() && cgroup["NeedsActivation"].asBool()) {
        controller_flags |= CGROUPRC_CONTROLLER_FLAG_NEEDS_ACTIVATION;
    }

    if (cgroup["Optional"].isBool() && cgroup["Optional"].asBool()) {
        controller_flags |= CGROUPRC_CONTROLLER_FLAG_OPTIONAL;
    }

    uint32_t max_activation_depth = UINT32_MAX;
    if (cgroup.isMember("MaxActivationDepth")) {
        max_activation_depth = cgroup["MaxActivationDepth"].asUInt();
    }

    CgroupDescriptor descriptor(
            cgroups_version, name, path, std::strtoul(cgroup["Mode"].asString().c_str(), 0, 8),
            cgroup["UID"].asString(), cgroup["GID"].asString(), controller_flags,
            max_activation_depth);

    auto iter = descriptors->find(name);
    if (iter == descriptors->end()) {
        descriptors->emplace(name, descriptor);
    } else {
        iter->second = descriptor;
    }
}

bool ReadDescriptorsFromFile(const std::string& file_name, CgroupDescriptorMap* descriptors) {
    static constexpr bool force_memcg_v2 = android::libprocessgroup_flags::force_memcg_v2();
    std::vector<CgroupDescriptor> result;
    std::string json_doc;

    if (!android::base::ReadFileToString(file_name, &json_doc)) {
        PLOG(ERROR) << "Failed to read task profiles from " << file_name;
        return false;
    }

    Json::CharReaderBuilder builder;
    std::unique_ptr<Json::CharReader> reader(builder.newCharReader());
    Json::Value root;
    std::string errorMessage;
    if (!reader->parse(&*json_doc.begin(), &*json_doc.end(), &root, &errorMessage)) {
        LOG(ERROR) << "Failed to parse cgroups description: " << errorMessage;
        return false;
    }

    if (root.isMember("Cgroups")) {
        const Json::Value& cgroups = root["Cgroups"];
        for (Json::Value::ArrayIndex i = 0; i < cgroups.size(); ++i) {
            std::string name = cgroups[i]["Controller"].asString();

            if (force_memcg_v2 && name == "memory") continue;

            MergeCgroupToDescriptors(descriptors, cgroups[i], name, "", 1);
        }
    }

    bool memcgv2_present = false;
    std::string root_path;
    if (root.isMember("Cgroups2")) {
        const Json::Value& cgroups2 = root["Cgroups2"];
        root_path = cgroups2["Path"].asString();
        MergeCgroupToDescriptors(descriptors, cgroups2, CGROUPV2_HIERARCHY_NAME_INTERNAL, "", 2);

        const Json::Value& childGroups = cgroups2["Controllers"];
        for (Json::Value::ArrayIndex i = 0; i < childGroups.size(); ++i) {
            std::string name = childGroups[i]["Controller"].asString();

            if (force_memcg_v2 && name == "memory") memcgv2_present = true;

            MergeCgroupToDescriptors(descriptors, childGroups[i], name, root_path, 2);
        }
    }

    if (force_memcg_v2 && !memcgv2_present) {
        LOG(INFO) << "Forcing memcg to v2 hierarchy";
        Json::Value memcgv2;
        memcgv2["Controller"] = "memory";
        memcgv2["NeedsActivation"] = true;
        memcgv2["Path"] = ".";
        memcgv2["Optional"] = true;  // In case of cgroup_disabled=memory, so we can still boot
        MergeCgroupToDescriptors(descriptors, memcgv2, "memory",
                                 root_path.empty() ? CGROUP_V2_ROOT_DEFAULT : root_path, 2);
    }

    return true;
}

using MountDir = std::string;
using MountOpts = std::string;
static std::optional<std::map<MountDir, MountOpts>> ReadCgroupV1Mounts() {
    FILE* fp = setmntent("/proc/mounts", "r");
    if (fp == nullptr) {
        PLOG(ERROR) << "Failed to read mounts";
        return std::nullopt;
    }

    std::map<MountDir, MountOpts> mounts;
    const std::string_view CGROUP_V1_TYPE = "cgroup";
    for (mntent* mentry = getmntent(fp); mentry != nullptr; mentry = getmntent(fp)) {
        if (mentry->mnt_type && CGROUP_V1_TYPE == mentry->mnt_type &&
            mentry->mnt_dir && mentry->mnt_opts) {
            mounts[mentry->mnt_dir] = mentry->mnt_opts;
        }
    }
    endmntent(fp);

    return mounts;
}

}  // anonymous namespace


unsigned int GetCgroupDepth(const std::string& controller_root, const std::string& cgroup_path) {
    const std::string deduped_root = DeduplicateAndTrimSeparators(controller_root);
    const std::string deduped_path = DeduplicateAndTrimSeparators(cgroup_path);

    if (deduped_root.empty() || deduped_path.empty() || !deduped_path.starts_with(deduped_root))
        return 0;

    return std::count(deduped_path.begin() + deduped_root.size(), deduped_path.end(), SEP);
}

bool ReadDescriptors(CgroupDescriptorMap* descriptors) {
    // load system cgroup descriptors
    if (!ReadDescriptorsFromFile(CGROUPS_DESC_FILE, descriptors)) {
        return false;
    }

    // load API-level specific system cgroups descriptors if available
    unsigned int api_level = GetUintProperty<unsigned int>("ro.product.first_api_level", 0);
    if (api_level > 0) {
        std::string api_cgroups_path =
                android::base::StringPrintf(TEMPLATE_CGROUPS_DESC_API_FILE, api_level);
        if (!access(api_cgroups_path.c_str(), F_OK) || errno != ENOENT) {
            if (!ReadDescriptorsFromFile(api_cgroups_path, descriptors)) {
                return false;
            }
        }
    }

    // load vendor cgroup descriptors if the file exists
    if (!access(CGROUPS_DESC_VENDOR_FILE, F_OK) &&
        !ReadDescriptorsFromFile(CGROUPS_DESC_VENDOR_FILE, descriptors)) {
        return false;
    }

    // check for v1 mount/usability status
    std::optional<std::map<MountDir, MountOpts>> v1Mounts;
    for (auto& [name, descriptor] : *descriptors) {
        const CgroupController* const controller = descriptor.controller();

        if (controller->version() != 1) continue;

        // Read only once, and only if we have at least one v1 controller
        if (!v1Mounts) {
            v1Mounts = ReadCgroupV1Mounts();
            if (!v1Mounts) return false;
        }

        if (const auto it = v1Mounts->find(controller->path()); it != v1Mounts->end()) {
            if (it->second.contains(controller->name())) descriptor.set_mounted(true);
        }
    }

    return true;
}
