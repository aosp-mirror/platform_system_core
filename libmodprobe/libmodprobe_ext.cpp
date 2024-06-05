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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include <modprobe/modprobe.h>

std::string Modprobe::GetKernelCmdline(void) {
    std::string cmdline;
    if (!android::base::ReadFileToString("/proc/cmdline", &cmdline)) {
        return "";
    }
    return cmdline;
}

bool Modprobe::Insmod(const std::string& path_name, const std::string& parameters) {
    android::base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(path_name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) {
        PLOG(ERROR) << "Could not open module '" << path_name << "'";
        return false;
    }

    auto canonical_name = MakeCanonical(path_name);
    std::string options = "";
    auto options_iter = module_options_.find(canonical_name);
    if (options_iter != module_options_.end()) {
        options = options_iter->second;
    }
    if (!parameters.empty()) {
        options = options + " " + parameters;
    }

    LOG(INFO) << "Loading module " << path_name << " with args '" << options << "'";
    int ret = syscall(__NR_finit_module, fd.get(), options.c_str(), 0);
    if (ret != 0) {
        if (errno == EEXIST) {
            // Module already loaded
            std::lock_guard guard(module_loaded_lock_);
            module_loaded_paths_.emplace(path_name);
            module_loaded_.emplace(canonical_name);
            return true;
        }
        PLOG(ERROR) << "Failed to insmod '" << path_name << "' with args '" << options << "'";
        return false;
    }

    LOG(INFO) << "Loaded kernel module " << path_name;
    std::lock_guard guard(module_loaded_lock_);
    module_loaded_paths_.emplace(path_name);
    module_loaded_.emplace(canonical_name);
    module_count_++;
    return true;
}

bool Modprobe::Rmmod(const std::string& module_name) {
    auto canonical_name = MakeCanonical(module_name);
    int ret = syscall(__NR_delete_module, canonical_name.c_str(), O_NONBLOCK);
    if (ret != 0) {
        PLOG(ERROR) << "Failed to remove module '" << module_name << "'";
        return false;
    }
    std::lock_guard guard(module_loaded_lock_);
    module_loaded_.erase(canonical_name);
    return true;
}

bool Modprobe::ModuleExists(const std::string& module_name) {
    struct stat fileStat {};
    if (blocklist_enabled && module_blocklist_.count(module_name)) {
        LOG(INFO) << "module " << module_name << " is blocklisted";
        return false;
    }
    auto deps = GetDependencies(module_name);
    if (deps.empty()) {
        // missing deps can happen in the case of an alias
        return false;
    }
    if (stat(deps.front().c_str(), &fileStat)) {
        PLOG(INFO) << "module " << module_name << " can't be loaded; can't access " << deps.front();
        return false;
    }
    if (!S_ISREG(fileStat.st_mode)) {
        LOG(INFO) << "module " << module_name << " is not a regular file";
        return false;
    }
    return true;
}
