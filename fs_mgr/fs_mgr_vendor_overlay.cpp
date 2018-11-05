/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <dirent.h>
#include <selinux/selinux.h>
#include <sys/mount.h>
#include <unistd.h>

#include <memory>
#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <fs_mgr_overlayfs.h>
#include <fs_mgr_vendor_overlay.h>
#include <fstab/fstab.h>

#include "fs_mgr_priv.h"

using namespace std::literals;

namespace {

const auto kVendorOverlaySourceDir = "/system/vendor_overlay/"s;
const auto kVndkVersionPropertyName = "ro.vndk.version"s;
const auto kVendorTopDir = "/vendor/"s;
const auto kLowerdirOption = "lowerdir="s;

std::string fs_mgr_get_vendor_overlay_top_dir() {
    // VNDK version is provided by the /vendor/default.prop
    // To read the property, it must be called at the second init stage after the default
    // properties are loaded.
    std::string vndk_version = android::base::GetProperty(kVndkVersionPropertyName, "");
    if (vndk_version.empty()) {
        return "";
    }
    return kVendorOverlaySourceDir + vndk_version;
}

std::vector<std::string> fs_mgr_get_vendor_overlay_dirs(const std::string& overlay_top) {
    std::vector<std::string> vendor_overlay_dirs;
    std::unique_ptr<DIR, decltype(&closedir)> vendor_overlay_top(opendir(overlay_top.c_str()),
                                                                 closedir);
    if (!vendor_overlay_top) return vendor_overlay_dirs;

    // Vendor overlay root for current vendor version found!
    LINFO << "vendor overlay root: " << overlay_top;
    struct dirent* dp;
    while ((dp = readdir(vendor_overlay_top.get())) != nullptr) {
        if (dp->d_type != DT_DIR || dp->d_name[0] == '.') {
            continue;
        }
        vendor_overlay_dirs.push_back(dp->d_name);
    }

    return vendor_overlay_dirs;
}

bool fs_mgr_vendor_overlay_mount(const std::string& overlay_top, const std::string& mount_point) {
    const auto vendor_mount_point = kVendorTopDir + mount_point;
    LINFO << "vendor overlay mount on " << vendor_mount_point;

    const auto target_context = fs_mgr_get_context(vendor_mount_point);
    if (target_context.empty()) {
        PERROR << " failed: cannot find the target vendor mount point";
        return false;
    }
    const auto source_directory = overlay_top + "/" + mount_point;
    const auto source_context = fs_mgr_get_context(source_directory);
    if (target_context != source_context) {
        LERROR << " failed: source and target contexts do not match (source:" << source_context
               << ", target:" << target_context << ")";
        return false;
    }

    auto options =
            "override_creds=off,"s + kLowerdirOption + source_directory + ":" + vendor_mount_point;
    auto report = "__mount(source=overlay,target="s + vendor_mount_point + ",type=overlay," +
                  options + ")=";
    auto ret = mount("overlay", vendor_mount_point.c_str(), "overlay", MS_RDONLY | MS_RELATIME,
                     options.c_str());
    if (ret) {
        PERROR << report << ret;
        return false;
    } else {
        LINFO << report << ret;
        return true;
    }
}

}  // namespace

// Since the vendor overlay requires to know the version of the vendor partition,
// it is not possible to mount vendor overlay at the first stage that cannot
// initialize properties.
// To read the properties, vendor overlay must be mounted at the second stage, right
// after "property_load_boot_defaults()" is called.
bool fs_mgr_vendor_overlay_mount_all() {
    const auto overlay_top = fs_mgr_get_vendor_overlay_top_dir();
    if (overlay_top.empty()) {
        LINFO << "vendor overlay: vndk version not defined";
        return false;
    }
    const auto vendor_overlay_dirs = fs_mgr_get_vendor_overlay_dirs(overlay_top);
    if (vendor_overlay_dirs.empty()) return true;
    if (!fs_mgr_overlayfs_supports_override_creds()) {
        LINFO << "vendor overlay: kernel does not support overlayfs";
        return false;
    }

    // Mount each directory in /system/vendor_overlay/<ver> on /vendor
    auto ret = true;
    for (const auto& vendor_overlay_dir : vendor_overlay_dirs) {
        if (!fs_mgr_vendor_overlay_mount(overlay_top, vendor_overlay_dir)) {
            ret = false;
        }
    }
    return ret;
}
