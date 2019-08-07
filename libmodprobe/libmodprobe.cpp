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

#include <modprobe/modprobe.h>

#include <fnmatch.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <algorithm>
#include <set>
#include <string>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

std::string Modprobe::MakeCanonical(const std::string& module_path) {
    auto start = module_path.find_last_of('/');
    if (start == std::string::npos) {
        start = 0;
    } else {
        start += 1;
    }
    auto end = module_path.size();
    if (android::base::EndsWith(module_path, ".ko")) {
        end -= 3;
    }
    if ((end - start) <= 1) {
        LOG(ERROR) << "malformed module name: " << module_path;
        return "";
    }
    std::string module_name = module_path.substr(start, end - start);
    // module names can have '-', but their file names will have '_'
    std::replace(module_name.begin(), module_name.end(), '-', '_');
    return module_name;
}

bool Modprobe::ParseDepCallback(const std::string& base_path,
                                const std::vector<std::string>& args) {
    std::vector<std::string> deps;
    std::string prefix = "";

    // Set first item as our modules path
    std::string::size_type pos = args[0].find(':');
    if (args[0][0] != '/') {
        prefix = base_path + "/";
    }
    if (pos != std::string::npos) {
        deps.emplace_back(prefix + args[0].substr(0, pos));
    } else {
        LOG(ERROR) << "dependency lines must start with name followed by ':'";
    }

    // Remaining items are dependencies of our module
    for (auto arg = args.begin() + 1; arg != args.end(); ++arg) {
        if ((*arg)[0] != '/') {
            prefix = base_path + "/";
        } else {
            prefix = "";
        }
        deps.push_back(prefix + *arg);
    }

    std::string canonical_name = MakeCanonical(args[0].substr(0, pos));
    if (canonical_name.empty()) {
        return false;
    }
    this->module_deps_[canonical_name] = deps;

    return true;
}

bool Modprobe::ParseAliasCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "alias") {
        LOG(ERROR) << "non-alias line encountered in modules.alias, found " << type;
        return false;
    }

    if (args.size() != 3) {
        LOG(ERROR) << "alias lines in modules.alias must have 3 entries, not " << args.size();
        return false;
    }

    const std::string& alias = *it++;
    const std::string& module_name = *it++;
    this->module_aliases_.emplace_back(alias, module_name);

    return true;
}

bool Modprobe::ParseSoftdepCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;
    std::string state = "";

    if (type != "softdep") {
        LOG(ERROR) << "non-softdep line encountered in modules.softdep, found " << type;
        return false;
    }

    if (args.size() < 4) {
        LOG(ERROR) << "softdep lines in modules.softdep must have at least 4 entries";
        return false;
    }

    const std::string& module = *it++;
    while (it != args.end()) {
        const std::string& token = *it++;
        if (token == "pre:" || token == "post:") {
            state = token;
            continue;
        }
        if (state == "") {
            LOG(ERROR) << "malformed modules.softdep at token " << token;
            return false;
        }
        if (state == "pre:") {
            this->module_pre_softdep_.emplace_back(module, token);
        } else {
            this->module_post_softdep_.emplace_back(module, token);
        }
    }

    return true;
}

bool Modprobe::ParseLoadCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& module = *it++;

    const std::string& canonical_name = MakeCanonical(module);
    if (canonical_name.empty()) {
        return false;
    }
    this->module_load_.emplace_back(canonical_name);

    return true;
}

bool Modprobe::ParseOptionsCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "options") {
        LOG(ERROR) << "non-options line encountered in modules.options";
        return false;
    }

    if (args.size() < 2) {
        LOG(ERROR) << "lines in modules.options must have at least 2 entries, not " << args.size();
        return false;
    }

    const std::string& module = *it++;
    std::string options = "";

    const std::string& canonical_name = MakeCanonical(module);
    if (canonical_name.empty()) {
        return false;
    }

    while (it != args.end()) {
        options += *it++;
        if (it != args.end()) {
            options += " ";
        }
    }

    auto [unused, inserted] = this->module_options_.emplace(canonical_name, options);
    if (!inserted) {
        LOG(ERROR) << "multiple options lines present for module " << module;
        return false;
    }
    return true;
}

void Modprobe::ParseCfg(const std::string& cfg,
                        std::function<bool(const std::vector<std::string>&)> f) {
    std::string cfg_contents;
    if (!android::base::ReadFileToString(cfg, &cfg_contents, false)) {
        return;
    }

    std::vector<std::string> lines = android::base::Split(cfg_contents, "\n");
    for (const std::string line : lines) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::vector<std::string> args = android::base::Split(line, " ");
        if (args.empty()) continue;
        f(args);
    }
    return;
}

Modprobe::Modprobe(const std::vector<std::string>& base_paths) {
    using namespace std::placeholders;

    for (const auto& base_path : base_paths) {
        auto alias_callback = std::bind(&Modprobe::ParseAliasCallback, this, _1);
        ParseCfg(base_path + "/modules.alias", alias_callback);

        auto dep_callback = std::bind(&Modprobe::ParseDepCallback, this, base_path, _1);
        ParseCfg(base_path + "/modules.dep", dep_callback);

        auto softdep_callback = std::bind(&Modprobe::ParseSoftdepCallback, this, _1);
        ParseCfg(base_path + "/modules.softdep", softdep_callback);

        auto load_callback = std::bind(&Modprobe::ParseLoadCallback, this, _1);
        ParseCfg(base_path + "/modules.load", load_callback);

        auto options_callback = std::bind(&Modprobe::ParseOptionsCallback, this, _1);
        ParseCfg(base_path + "/modules.options", options_callback);
    }
}

std::vector<std::string> Modprobe::GetDependencies(const std::string& module) {
    auto it = module_deps_.find(module);
    if (it == module_deps_.end()) {
        return {};
    }
    return it->second;
}

bool Modprobe::InsmodWithDeps(const std::string& module_name) {
    if (module_name.empty()) {
        LOG(ERROR) << "Need valid module name, given: " << module_name;
        return false;
    }

    auto dependencies = GetDependencies(module_name);
    if (dependencies.empty()) {
        LOG(ERROR) << "Module " << module_name << " not in dependency file";
        return false;
    }

    // load module dependencies in reverse order
    for (auto dep = dependencies.rbegin(); dep != dependencies.rend() - 1; ++dep) {
        if (!LoadWithAliases(*dep, true)) {
            return false;
        }
    }

    // try to load soft pre-dependencies
    for (const auto& [module, softdep] : module_pre_softdep_) {
        if (module_name == module) {
            LoadWithAliases(softdep, false);
        }
    }

    // load target module itself with args
    if (!Insmod(dependencies[0])) {
        return false;
    }

    // try to load soft post-dependencies
    for (const auto& [module, softdep] : module_post_softdep_) {
        if (module_name == module) {
            LoadWithAliases(softdep, false);
        }
    }

    return true;
}

bool Modprobe::LoadWithAliases(const std::string& module_name, bool strict) {
    std::set<std::string> modules_to_load = {MakeCanonical(module_name)};
    bool module_loaded = false;

    // use aliases to expand list of modules to load (multiple modules
    // may alias themselves to the requested name)
    for (const auto& [alias, aliased_module] : module_aliases_) {
        if (fnmatch(alias.c_str(), module_name.c_str(), 0) != 0) continue;
        modules_to_load.emplace(aliased_module);
    }

    // attempt to load all modules aliased to this name
    for (const auto& module : modules_to_load) {
        if (!ModuleExists(module)) continue;
        if (InsmodWithDeps(module)) module_loaded = true;
    }

    if (strict && !module_loaded) {
        LOG(ERROR) << "LoadWithAliases did not find a module for " << module_name;
        return false;
    }
    return true;
}

bool Modprobe::LoadListedModules() {
    for (const auto& module : module_load_) {
        if (!LoadWithAliases(module, true)) {
            return false;
        }
    }
    return true;
}

bool Modprobe::Remove(const std::string& module_name) {
    auto dependencies = GetDependencies(MakeCanonical(module_name));
    if (dependencies.empty()) {
        LOG(ERROR) << "Empty dependencies for module " << module_name;
        return false;
    }
    if (!Rmmod(dependencies[0])) {
        return false;
    }
    for (auto dep = dependencies.begin() + 1; dep != dependencies.end(); ++dep) {
        Rmmod(*dep);
    }
    return true;
}
