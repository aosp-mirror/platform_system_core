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

#include <sys/stat.h>
#include <sys/syscall.h>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <modprobe/modprobe.h>

bool Modprobe::Insmod(const std::string& path_name, const std::string& parameters) {
    android::base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(path_name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        LOG(ERROR) << "Could not open module '" << path_name << "'";
        return false;
    }

    std::string options = "";
    auto options_iter = module_options_.find(MakeCanonical(path_name));
    if (options_iter != module_options_.end()) {
        options = options_iter->second;
    }
    if (!parameters.empty()) {
        options = options + " " + parameters;
    }

    LOG(INFO) << "Loading module " << path_name << " with args \"" << options << "\"";
    int ret = syscall(__NR_finit_module, fd.get(), options.c_str(), 0);
    if (ret != 0) {
        if (errno == EEXIST) {
            // Module already loaded
            return true;
        }
        LOG(ERROR) << "Failed to insmod '" << path_name << "' with args '" << options << "'";
        return false;
    }

    LOG(INFO) << "Loaded kernel module " << path_name;
    return true;
}

bool Modprobe::Rmmod(const std::string& module_name) {
    int ret = syscall(__NR_delete_module, MakeCanonical(module_name).c_str(), O_NONBLOCK);
    if (ret != 0) {
        PLOG(ERROR) << "Failed to remove module '" << module_name << "'";
        return false;
    }
    return true;
}

bool Modprobe::ModuleExists(const std::string& module_name) {
    struct stat fileStat;
    if (blacklist_enabled && module_blacklist_.count(module_name)) {
        return false;
    }
    auto deps = GetDependencies(module_name);
    if (deps.empty()) {
        // missing deps can happen in the case of an alias
        return false;
    }
    if (stat(deps.front().c_str(), &fileStat)) {
        return false;
    }
    if (!S_ISREG(fileStat.st_mode)) {
        return false;
    }
    return true;
}
