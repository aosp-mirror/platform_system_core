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

#include "modalias_handler.h"

#include <fnmatch.h>
#include <sys/syscall.h>

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "parser.h"

namespace android {
namespace init {

Result<Success> ModaliasHandler::ParseDepCallback(std::vector<std::string>&& args) {
    std::vector<std::string> deps;

    // Set first item as our modules path
    std::string::size_type pos = args[0].find(':');
    if (pos != std::string::npos) {
        deps.emplace_back(args[0].substr(0, pos));
    } else {
        return Error() << "dependency lines must start with name followed by ':'";
    }

    // Remaining items are dependencies of our module
    for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
        deps.push_back(*arg);
    }

    // Key is striped module name to match names in alias file
    std::size_t start = args[0].find_last_of("/");
    std::size_t end = args[0].find(".ko:");
    if ((end - start) <= 1) return Error() << "malformed dependency line";
    auto mod_name = args[0].substr(start + 1, (end - start) - 1);
    // module names can have '-', but their file names will have '_'
    std::replace(mod_name.begin(), mod_name.end(), '-', '_');
    this->module_deps_[mod_name] = deps;

    return Success();
}

Result<Success> ModaliasHandler::ParseAliasCallback(std::vector<std::string>&& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "alias") {
        return Error() << "we only handle alias lines, got: " << type;
    }

    if (args.size() != 3) {
        return Error() << "alias lines must have 3 entries";
    }

    std::string& alias = *it++;
    std::string& module_name = *it++;
    this->module_aliases_.emplace_back(alias, module_name);

    return Success();
}

ModaliasHandler::ModaliasHandler() {
    using namespace std::placeholders;

    static const std::string base_paths[] = {
            "/vendor/lib/modules/",
            "/lib/modules/",
            "/odm/lib/modules/",
    };

    Parser alias_parser;
    auto alias_callback = std::bind(&ModaliasHandler::ParseAliasCallback, this, _1);
    alias_parser.AddSingleLineParser("alias", alias_callback);
    for (const auto& base_path : base_paths) alias_parser.ParseConfig(base_path + "modules.alias");

    Parser dep_parser;
    auto dep_callback = std::bind(&ModaliasHandler::ParseDepCallback, this, _1);
    dep_parser.AddSingleLineParser("", dep_callback);
    for (const auto& base_path : base_paths) dep_parser.ParseConfig(base_path + "modules.dep");
}

Result<Success> ModaliasHandler::Insmod(const std::string& path_name, const std::string& args) {
    base::unique_fd fd(
            TEMP_FAILURE_RETRY(open(path_name.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC)));
    if (fd == -1) return ErrnoError() << "Could not open module '" << path_name << "'";

    int ret = syscall(__NR_finit_module, fd.get(), args.c_str(), 0);
    if (ret != 0) {
        if (errno == EEXIST) {
            // Module already loaded
            return Success();
        }
        return ErrnoError() << "Failed to insmod '" << path_name << "' with args '" << args << "'";
    }

    LOG(INFO) << "Loaded kernel module " << path_name;
    return Success();
}

Result<Success> ModaliasHandler::InsmodWithDeps(const std::string& module_name,
                                                const std::string& args) {
    if (module_name.empty()) {
        return Error() << "Need valid module name";
    }

    auto it = module_deps_.find(module_name);
    if (it == module_deps_.end()) {
        return Error() << "Module '" << module_name << "' not in dependency file";
    }
    auto& dependencies = it->second;

    // load module dependencies in reverse order
    for (auto dep = dependencies.rbegin(); dep != dependencies.rend() - 1; ++dep) {
        if (auto result = Insmod(*dep, ""); !result) return result;
    }

    // load target module itself with args
    return Insmod(dependencies[0], args);
}

void ModaliasHandler::HandleModaliasEvent(const Uevent& uevent) {
    if (uevent.modalias.empty()) return;

    for (const auto& [alias, module] : module_aliases_) {
        if (fnmatch(alias.c_str(), uevent.modalias.c_str(), 0) != 0) continue;  // Keep looking

        LOG(DEBUG) << "Loading kernel module '" << module << "' for alias '" << uevent.modalias
                   << "'";

        if (auto result = InsmodWithDeps(module, ""); !result) {
            LOG(ERROR) << "Cannot load module: " << result.error();
            // try another one since there may be another match
            continue;
        }

        // loading was successful
        return;
    }
}

}  // namespace init
}  // namespace android
