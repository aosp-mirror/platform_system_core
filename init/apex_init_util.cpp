/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "apex_init_util.h"

#include <dirent.h>
#include <glob.h>

#include <set>
#include <vector>

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/result.h>
#include <android-base/strings.h>

#include "action_manager.h"
#include "init.h"
#include "parser.h"
#include "service_list.h"
#include "util.h"

namespace android {
namespace init {

static Result<std::vector<std::string>> CollectRcScriptsFromApex(
        const std::string& apex_name, const std::set<std::string>& skip_apexes) {
    glob_t glob_result;
    // Pattern uses "*rc" instead of ".rc" because APEXes can have versioned RC files
    // like foo.34rc.
    std::string glob_pattern =
            apex_name.empty() ? "/apex/*/etc/*rc" : "/apex/" + apex_name + "/etc/*rc";

    const int ret = glob(glob_pattern.c_str(), GLOB_MARK, nullptr, &glob_result);
    if (ret != 0 && ret != GLOB_NOMATCH) {
        globfree(&glob_result);
        return Error() << "Glob pattern '" << glob_pattern << "' failed";
    }
    std::vector<std::string> configs;
    for (size_t i = 0; i < glob_result.gl_pathc; i++) {
        std::string path = glob_result.gl_pathv[i];

        // Filter out directories
        if (path.back() == '/') {
            continue;
        }

        // Get apex name from path.
        std::vector<std::string> paths = android::base::Split(path, "/");
        if (paths.size() < 3) {
            continue;
        }
        const std::string& apex_name = paths[2];

        // Filter out /apex/<name>@<ver> paths. The paths are bind-mounted to
        // /apex/<name> paths, so unless we filter them out, we will parse the
        // same file twice.
        if (apex_name.find('@') != std::string::npos) {
            continue;
        }

        // Filter out skip_set apexes
        if (skip_apexes.count(apex_name) > 0) {
            continue;
        }
        configs.push_back(path);
    }
    globfree(&glob_result);
    return configs;
}

std::set<std::string> GetApexListFrom(const std::string& apex_dir) {
    std::set<std::string> apex_list;
    auto dirp = std::unique_ptr<DIR, int (*)(DIR*)>(opendir(apex_dir.c_str()), closedir);
    if (!dirp) {
        return apex_list;
    }
    struct dirent* entry;
    while ((entry = readdir(dirp.get())) != nullptr) {
        if (entry->d_type != DT_DIR) continue;

        const char* name = entry->d_name;
        if (name[0] == '.') continue;
        if (strchr(name, '@') != nullptr) continue;
        if (strcmp(name, "sharedlibs") == 0) continue;
        apex_list.insert(name);
    }
    return apex_list;
}

static Result<void> ParseRcScripts(const std::vector<std::string>& files) {
    if (files.empty()) {
        return {};
    }
    // APEXes can have versioned RC files. These should be filtered based on
    // SDK version.
    int sdk = android::base::GetIntProperty("ro.build.version.sdk", INT_MAX);
    if (sdk < 35) sdk = 35;  // aosp/main merges only into sdk=35+ (ie. __ANDROID_API_V__+)
    auto filtered = FilterVersionedConfigs(files, sdk);
    if (filtered.empty()) {
        return {};
    }

    Parser parser =
            CreateApexConfigParser(ActionManager::GetInstance(), ServiceList::GetInstance());
    std::vector<std::string> errors;
    for (const auto& c : filtered) {
        auto result = parser.ParseConfigFile(c);
        // We should handle other config files even when there's an error.
        if (!result.ok()) {
            errors.push_back(result.error().message());
        }
    }
    if (!errors.empty()) {
        return Error() << "Unable to parse apex configs: " << base::Join(errors, "|");
    }
    return {};
}

Result<void> ParseRcScriptsFromApex(const std::string& apex_name) {
    auto configs = OR_RETURN(CollectRcScriptsFromApex(apex_name, /*skip_apexes=*/{}));
    return ParseRcScripts(configs);
}

Result<void> ParseRcScriptsFromAllApexes(bool bootstrap) {
    std::set<std::string> skip_apexes;
    if (!bootstrap) {
        // In case we already loaded config files from bootstrap APEXes, we need to avoid loading
        // them again. We can get the list of bootstrap APEXes by scanning /bootstrap-apex and
        // skip them in CollectRcScriptsFromApex.
        skip_apexes = GetApexListFrom("/bootstrap-apex");
    }
    auto configs = OR_RETURN(CollectRcScriptsFromApex(/*apex_name=*/"", skip_apexes));
    return ParseRcScripts(configs);
}

}  // namespace init
}  // namespace android
