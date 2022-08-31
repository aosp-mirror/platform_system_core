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

#include <glob.h>

#include <map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/result.h>
#include <android-base/properties.h>
#include <android-base/strings.h>

#include "action_manager.h"
#include "init.h"
#include "parser.h"
#include "service_list.h"
#include "util.h"

namespace android {
namespace init {

static Result<std::vector<std::string>> CollectApexConfigs(const std::string& apex_name) {
    glob_t glob_result;
    std::string glob_pattern = apex_name.empty() ?
            "/apex/*/etc/*rc" : "/apex/" + apex_name + "/etc/*rc";

    const int ret = glob(glob_pattern.c_str(), GLOB_MARK, nullptr, &glob_result);
    if (ret != 0 && ret != GLOB_NOMATCH) {
        globfree(&glob_result);
        return Error() << "Glob pattern '" << glob_pattern << "' failed";
    }
    std::vector<std::string> configs;
    for (size_t i = 0; i < glob_result.gl_pathc; i++) {
        std::string path = glob_result.gl_pathv[i];
        // Filter-out /apex/<name>@<ver> paths. The paths are bind-mounted to
        // /apex/<name> paths, so unless we filter them out, we will parse the
        // same file twice.
        std::vector<std::string> paths = android::base::Split(path, "/");
        if (paths.size() >= 3 && paths[2].find('@') != std::string::npos) {
            continue;
        }
        // Filter directories
        if (path.back() == '/') {
            continue;
        }
        configs.push_back(path);
    }
    globfree(&glob_result);
    return configs;
}

static Result<void> ParseConfigs(const std::vector<std::string>& configs) {
    Parser parser = CreateApexConfigParser(ActionManager::GetInstance(),
                     ServiceList::GetInstance());
    bool success = true;
    for (const auto& c : configs) {
        success &= parser.ParseConfigFile(c);
    }

    if (success) {
        return {};
    } else {
        return Error() << "Unable to parse apex configs";
    }
}

Result<void> ParseApexConfigs(const std::string& apex_name) {
    Result<std::vector<std::string>> configs = CollectApexConfigs(apex_name);
    if (!configs.ok()) {
        return configs.error();
    }

    if (configs.value().empty()) {
        return {};
    }

    auto filtered_configs = FilterVersionedConfigs(configs.value(),
                                    android::base::GetIntProperty("ro.build.version.sdk", INT_MAX));
    return ParseConfigs(filtered_configs);
}

}  // namespace init
}  // namespace android
