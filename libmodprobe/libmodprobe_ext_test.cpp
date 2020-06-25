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

#include <sys/stat.h>
#include <sys/syscall.h>

#include <string>
#include <vector>

#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <gtest/gtest.h>

#include <modprobe/modprobe.h>

#include "libmodprobe_test.h"

std::string Modprobe::GetKernelCmdline(void) {
    return kernel_cmdline;
}

bool Modprobe::Insmod(const std::string& path_name, const std::string& parameters) {
    auto deps = GetDependencies(MakeCanonical(path_name));
    if (deps.empty()) {
        return false;
    }
    if (std::find(test_modules.begin(), test_modules.end(), deps.front()) == test_modules.end()) {
        return false;
    }
    for (auto it = modules_loaded.begin(); it != modules_loaded.end(); ++it) {
        if (android::base::StartsWith(*it, path_name)) {
            return true;
        }
    }
    std::string options;
    auto options_iter = module_options_.find(MakeCanonical(path_name));
    if (options_iter != module_options_.end()) {
        options = " " + options_iter->second;
    }
    if (!parameters.empty()) {
        options = options + " " + parameters;
    }

    modules_loaded.emplace_back(path_name + options);
    module_count_++;
    return true;
}

bool Modprobe::Rmmod(const std::string& module_name) {
    for (auto it = modules_loaded.begin(); it != modules_loaded.end(); it++) {
        if (*it == module_name || android::base::StartsWith(*it, module_name + " ")) {
            modules_loaded.erase(it);
            return true;
        }
    }
    return false;
}

bool Modprobe::ModuleExists(const std::string& module_name) {
    auto deps = GetDependencies(module_name);
    if (blocklist_enabled && module_blocklist_.count(module_name)) {
        return false;
    }
    if (deps.empty()) {
        // missing deps can happen in the case of an alias
        return false;
    }
    return std::find(test_modules.begin(), test_modules.end(), deps.front()) != test_modules.end();
}
