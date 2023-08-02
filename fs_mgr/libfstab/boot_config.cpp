/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <algorithm>
#include <iterator>
#include <string>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "fstab_priv.h"
#include "logging_macros.h"

namespace android {
namespace fs_mgr {

const std::string& GetAndroidDtDir() {
    // Set once and saves time for subsequent calls to this function
    static const std::string kAndroidDtDir = [] {
        std::string android_dt_dir;
        if ((GetBootconfig("androidboot.android_dt_dir", &android_dt_dir) ||
             GetKernelCmdline("androidboot.android_dt_dir", &android_dt_dir)) &&
            !android_dt_dir.empty()) {
            // Ensure the returned path ends with a /
            if (android_dt_dir.back() != '/') {
                android_dt_dir.push_back('/');
            }
        } else {
            // Fall back to the standard procfs-based path
            android_dt_dir = "/proc/device-tree/firmware/android/";
        }
        LINFO << "Using Android DT directory " << android_dt_dir;
        return android_dt_dir;
    }();
    return kAndroidDtDir;
}

void ImportBootconfigFromString(const std::string& bootconfig,
                                const std::function<void(std::string, std::string)>& fn) {
    for (std::string_view line : android::base::Split(bootconfig, "\n")) {
        const auto equal_pos = line.find('=');
        std::string key = android::base::Trim(line.substr(0, equal_pos));
        if (key.empty()) {
            continue;
        }
        std::string value;
        if (equal_pos != line.npos) {
            value = android::base::Trim(line.substr(equal_pos + 1));
            // If the value is a comma-delimited list, the kernel would insert a space between the
            // list elements when read from /proc/bootconfig.
            // BoardConfig.mk:
            //      BOARD_BOOTCONFIG := key=value1,value2,value3
            // /proc/bootconfig:
            //      key = "value1", "value2", "value3"
            if (key == "androidboot.boot_device" || key == "androidboot.boot_devices") {
                // boot_device[s] is a special case where a list element can contain comma and the
                // caller expects a space-delimited list, so don't remove space here.
                value.erase(std::remove(value.begin(), value.end(), '"'), value.end());
            } else {
                // In order to not break the expectations of existing code, we modify the value to
                // keep the format consistent with the kernel cmdline by removing quote and space.
                std::string_view sv(value);
                android::base::ConsumePrefix(&sv, "\"");
                android::base::ConsumeSuffix(&sv, "\"");
                value = android::base::StringReplace(sv, R"(", ")", ",", true);
            }
        }
        // "key" and "key =" means empty value.
        fn(std::move(key), std::move(value));
    }
}

bool GetBootconfigFromString(const std::string& bootconfig, const std::string& key,
                             std::string* out) {
    bool found = false;
    ImportBootconfigFromString(bootconfig, [&](std::string config_key, std::string value) {
        if (!found && config_key == key) {
            *out = std::move(value);
            found = true;
        }
    });
    return found;
}

void ImportBootconfig(const std::function<void(std::string, std::string)>& fn) {
    std::string bootconfig;
    android::base::ReadFileToString("/proc/bootconfig", &bootconfig);
    ImportBootconfigFromString(bootconfig, fn);
}

bool GetBootconfig(const std::string& key, std::string* out) {
    std::string bootconfig;
    android::base::ReadFileToString("/proc/bootconfig", &bootconfig);
    return GetBootconfigFromString(bootconfig, key, out);
}

void ImportKernelCmdlineFromString(const std::string& cmdline,
                                   const std::function<void(std::string, std::string)>& fn) {
    static constexpr char quote = '"';

    size_t base = 0;
    while (true) {
        // skip quoted spans
        auto found = base;
        while (((found = cmdline.find_first_of(" \"", found)) != cmdline.npos) &&
               (cmdline[found] == quote)) {
            // unbalanced quote is ok
            if ((found = cmdline.find(quote, found + 1)) == cmdline.npos) break;
            ++found;
        }
        std::string piece = cmdline.substr(base, found - base);
        piece.erase(std::remove(piece.begin(), piece.end(), quote), piece.end());
        auto equal_sign = piece.find('=');
        if (equal_sign == piece.npos) {
            if (!piece.empty()) {
                // no difference between <key> and <key>=
                fn(std::move(piece), "");
            }
        } else {
            std::string value = piece.substr(equal_sign + 1);
            piece.resize(equal_sign);
            fn(std::move(piece), std::move(value));
        }
        if (found == cmdline.npos) break;
        base = found + 1;
    }
}

bool GetKernelCmdlineFromString(const std::string& cmdline, const std::string& key,
                                std::string* out) {
    bool found = false;
    ImportKernelCmdlineFromString(cmdline, [&](std::string config_key, std::string value) {
        if (!found && config_key == key) {
            *out = std::move(value);
            found = true;
        }
    });
    return found;
}

void ImportKernelCmdline(const std::function<void(std::string, std::string)>& fn) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);
    ImportKernelCmdlineFromString(android::base::Trim(cmdline), fn);
}

bool GetKernelCmdline(const std::string& key, std::string* out) {
    std::string cmdline;
    android::base::ReadFileToString("/proc/cmdline", &cmdline);
    return GetKernelCmdlineFromString(android::base::Trim(cmdline), key, out);
}

}  // namespace fs_mgr
}  // namespace android

// Tries to get the boot config value in device tree, properties, kernel bootconfig and kernel
// cmdline (in that order).
// Returns 'true' if successfully found, 'false' otherwise.
bool fs_mgr_get_boot_config(const std::string& key, std::string* out_val) {
    FSTAB_CHECK(out_val != nullptr);

    // firstly, check the device tree
    if (is_dt_compatible()) {
        std::string file_name = android::fs_mgr::GetAndroidDtDir() + key;
        if (android::base::ReadFileToString(file_name, out_val)) {
            if (!out_val->empty()) {
                out_val->pop_back();  // Trims the trailing '\0' out.
                return true;
            }
        }
    }

    // next, check if we have "ro.boot" property already
    *out_val = android::base::GetProperty("ro.boot." + key, "");
    if (!out_val->empty()) {
        return true;
    }

    // next, check if we have the property in bootconfig
    const std::string config_key = "androidboot." + key;
    if (android::fs_mgr::GetBootconfig(config_key, out_val)) {
        return true;
    }

    // finally, fallback to kernel cmdline, properties may not be ready yet
    if (android::fs_mgr::GetKernelCmdline(config_key, out_val)) {
        return true;
    }

    return false;
}
