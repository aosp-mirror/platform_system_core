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
#include <map>
#include <set>
#include <string>
#include <thread>
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
        return false;
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

bool Modprobe::ParseBlocklistCallback(const std::vector<std::string>& args) {
    auto it = args.begin();
    const std::string& type = *it++;

    if (type != "blocklist") {
        LOG(ERROR) << "non-blocklist line encountered in modules.blocklist";
        return false;
    }

    if (args.size() != 2) {
        LOG(ERROR) << "lines in modules.blocklist must have exactly 2 entries, not " << args.size();
        return false;
    }

    const std::string& module = *it++;

    const std::string& canonical_name = MakeCanonical(module);
    if (canonical_name.empty()) {
        return false;
    }
    this->module_blocklist_.emplace(canonical_name);

    return true;
}

void Modprobe::ParseCfg(const std::string& cfg,
                        std::function<bool(const std::vector<std::string>&)> f) {
    std::string cfg_contents;
    if (!android::base::ReadFileToString(cfg, &cfg_contents, false)) {
        return;
    }

    std::vector<std::string> lines = android::base::Split(cfg_contents, "\n");
    for (const auto& line : lines) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const std::vector<std::string> args = android::base::Split(line, " ");
        if (args.empty()) continue;
        f(args);
    }
    return;
}

void Modprobe::AddOption(const std::string& module_name, const std::string& option_name,
                         const std::string& value) {
    auto canonical_name = MakeCanonical(module_name);
    auto options_iter = module_options_.find(canonical_name);
    auto option_str = option_name + "=" + value;
    if (options_iter != module_options_.end()) {
        options_iter->second = options_iter->second + " " + option_str;
    } else {
        module_options_.emplace(canonical_name, option_str);
    }
}

void Modprobe::ParseKernelCmdlineOptions(void) {
    std::string cmdline = GetKernelCmdline();
    std::string module_name = "";
    std::string option_name = "";
    std::string value = "";
    bool in_module = true;
    bool in_option = false;
    bool in_value = false;
    bool in_quotes = false;
    int start = 0;

    for (int i = 0; i < cmdline.size(); i++) {
        if (cmdline[i] == '"') {
            in_quotes = !in_quotes;
        }

        if (in_quotes) continue;

        if (cmdline[i] == ' ') {
            if (in_value) {
                value = cmdline.substr(start, i - start);
                if (!module_name.empty() && !option_name.empty()) {
                    AddOption(module_name, option_name, value);
                }
            }
            module_name = "";
            option_name = "";
            value = "";
            in_value = false;
            start = i + 1;
            in_module = true;
            continue;
        }

        if (cmdline[i] == '.') {
            if (in_module) {
                module_name = cmdline.substr(start, i - start);
                start = i + 1;
                in_module = false;
            }
            in_option = true;
            continue;
        }

        if (cmdline[i] == '=') {
            if (in_option) {
                option_name = cmdline.substr(start, i - start);
                start = i + 1;
                in_option = false;
            }
            in_value = true;
            continue;
        }
    }
    if (in_value && !in_quotes) {
        value = cmdline.substr(start, cmdline.size() - start);
        if (!module_name.empty() && !option_name.empty()) {
            AddOption(module_name, option_name, value);
        }
    }
}

Modprobe::Modprobe(const std::vector<std::string>& base_paths, const std::string load_file,
                   bool use_blocklist)
    : blocklist_enabled(use_blocklist) {
    using namespace std::placeholders;

    for (const auto& base_path : base_paths) {
        auto alias_callback = std::bind(&Modprobe::ParseAliasCallback, this, _1);
        ParseCfg(base_path + "/modules.alias", alias_callback);

        auto dep_callback = std::bind(&Modprobe::ParseDepCallback, this, base_path, _1);
        ParseCfg(base_path + "/modules.dep", dep_callback);

        auto softdep_callback = std::bind(&Modprobe::ParseSoftdepCallback, this, _1);
        ParseCfg(base_path + "/modules.softdep", softdep_callback);

        auto load_callback = std::bind(&Modprobe::ParseLoadCallback, this, _1);
        ParseCfg(base_path + "/" + load_file, load_callback);

        auto options_callback = std::bind(&Modprobe::ParseOptionsCallback, this, _1);
        ParseCfg(base_path + "/modules.options", options_callback);

        auto blocklist_callback = std::bind(&Modprobe::ParseBlocklistCallback, this, _1);
        ParseCfg(base_path + "/modules.blocklist", blocklist_callback);
    }

    ParseKernelCmdlineOptions();
}

std::vector<std::string> Modprobe::GetDependencies(const std::string& module) {
    auto it = module_deps_.find(module);
    if (it == module_deps_.end()) {
        return {};
    }
    return it->second;
}

bool Modprobe::InsmodWithDeps(const std::string& module_name, const std::string& parameters) {
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
        LOG(VERBOSE) << "Loading hard dep for '" << module_name << "': " << *dep;
        if (!LoadWithAliases(*dep, true)) {
            return false;
        }
    }

    // try to load soft pre-dependencies
    for (const auto& [module, softdep] : module_pre_softdep_) {
        if (module_name == module) {
            LOG(VERBOSE) << "Loading soft pre-dep for '" << module << "': " << softdep;
            LoadWithAliases(softdep, false);
        }
    }

    // load target module itself with args
    if (!Insmod(dependencies[0], parameters)) {
        return false;
    }

    // try to load soft post-dependencies
    for (const auto& [module, softdep] : module_post_softdep_) {
        if (module_name == module) {
            LOG(VERBOSE) << "Loading soft post-dep for '" << module << "': " << softdep;
            LoadWithAliases(softdep, false);
        }
    }

    return true;
}

bool Modprobe::LoadWithAliases(const std::string& module_name, bool strict,
                               const std::string& parameters) {
    auto canonical_name = MakeCanonical(module_name);
    if (module_loaded_.count(canonical_name)) {
        return true;
    }

    std::set<std::string> modules_to_load = {canonical_name};
    bool module_loaded = false;

    // use aliases to expand list of modules to load (multiple modules
    // may alias themselves to the requested name)
    for (const auto& [alias, aliased_module] : module_aliases_) {
        if (fnmatch(alias.c_str(), module_name.c_str(), 0) != 0) continue;
        LOG(VERBOSE) << "Found alias for '" << module_name << "': '" << aliased_module;
        if (module_loaded_.count(MakeCanonical(aliased_module))) continue;
        modules_to_load.emplace(aliased_module);
    }

    // attempt to load all modules aliased to this name
    for (const auto& module : modules_to_load) {
        if (!ModuleExists(module)) continue;
        if (InsmodWithDeps(module, parameters)) module_loaded = true;
    }

    if (strict && !module_loaded) {
        LOG(ERROR) << "LoadWithAliases was unable to load " << module_name
                   << ", tried: " << android::base::Join(modules_to_load, ", ");
        return false;
    }
    return true;
}

bool Modprobe::IsBlocklisted(const std::string& module_name) {
    if (!blocklist_enabled) return false;

    auto canonical_name = MakeCanonical(module_name);
    auto dependencies = GetDependencies(canonical_name);
    for (auto dep = dependencies.begin(); dep != dependencies.end(); ++dep) {
        if (module_blocklist_.count(MakeCanonical(*dep))) return true;
    }

    return module_blocklist_.count(canonical_name) > 0;
}

// Another option to load kernel modules. load independent modules dependencies
// in parallel and then update dependency list of other remaining modules,
// repeat these steps until all modules are loaded.
// Discard all blocklist.
// Softdeps are taken care in InsmodWithDeps().
bool Modprobe::LoadModulesParallel(int num_threads) {
    bool ret = true;
    std::map<std::string, std::vector<std::string>> mod_with_deps;

    // Get dependencies
    for (const auto& module : module_load_) {
        // Skip blocklist modules
        if (IsBlocklisted(module)) {
            LOG(VERBOSE) << "LMP: Blocklist: Module " << module << " skipping...";
            continue;
        }
        auto dependencies = GetDependencies(MakeCanonical(module));
        if (dependencies.empty()) {
            LOG(ERROR) << "LMP: Hard-dep: Module " << module
                       << " not in .dep file";
            return false;
        }
        mod_with_deps[MakeCanonical(module)] = dependencies;
    }

    while (!mod_with_deps.empty()) {
        std::vector<std::thread> threads;
        std::vector<std::string> mods_path_to_load;
        std::mutex vector_lock;

        // Find independent modules
        for (const auto& [it_mod, it_dep] : mod_with_deps) {
            auto itd_last = it_dep.rbegin();
            if (itd_last == it_dep.rend())
                continue;

            auto cnd_last = MakeCanonical(*itd_last);
            // Hard-dependencies cannot be blocklisted
            if (IsBlocklisted(cnd_last)) {
                LOG(ERROR) << "LMP: Blocklist: Module-dep " << cnd_last
                           << " : failed to load module " << it_mod;
                return false;
            }

            std::string str = "load_sequential=1";
            auto it = module_options_[cnd_last].find(str);
            if (it != std::string::npos) {
                module_options_[cnd_last].erase(it, it + str.size());

                if (!LoadWithAliases(cnd_last, true)) {
                    return false;
                }
            } else {
                if (std::find(mods_path_to_load.begin(), mods_path_to_load.end(),
                            cnd_last) == mods_path_to_load.end()) {
                    mods_path_to_load.emplace_back(cnd_last);
                }
            }
        }

        // Load independent modules in parallel
        auto thread_function = [&] {
            std::unique_lock lk(vector_lock);
            while (!mods_path_to_load.empty()) {
                auto ret_load = true;
                auto mod_to_load = std::move(mods_path_to_load.back());
                mods_path_to_load.pop_back();

                lk.unlock();
                ret_load &= LoadWithAliases(mod_to_load, true);
                lk.lock();
                if (!ret_load) {
                    ret &= ret_load;
                }
            }
        };

        std::generate_n(std::back_inserter(threads), num_threads,
                        [&] { return std::thread(thread_function); });

        // Wait for the threads.
        for (auto& thread : threads) {
            thread.join();
        }

        if (!ret) return ret;

        std::lock_guard guard(module_loaded_lock_);
        // Remove loaded module form mod_with_deps and soft dependencies of other modules
        for (const auto& module_loaded : module_loaded_)
            mod_with_deps.erase(module_loaded);

        // Remove loaded module form dependencies of other modules which are not loaded yet
        for (const auto& module_loaded_path : module_loaded_paths_) {
            for (auto& [mod, deps] : mod_with_deps) {
                auto it = std::find(deps.begin(), deps.end(), module_loaded_path);
                if (it != deps.end()) {
                    deps.erase(it);
                }
            }
        }
    }

    return ret;
}

bool Modprobe::LoadListedModules(bool strict) {
    auto ret = true;
    for (const auto& module : module_load_) {
        if (!LoadWithAliases(module, true)) {
            if (IsBlocklisted(module)) continue;
            ret = false;
            if (strict) break;
        }
    }
    return ret;
}

bool Modprobe::Remove(const std::string& module_name) {
    auto dependencies = GetDependencies(MakeCanonical(module_name));
    for (auto dep = dependencies.begin(); dep != dependencies.end(); ++dep) {
        Rmmod(*dep);
    }
    Rmmod(module_name);
    return true;
}

std::vector<std::string> Modprobe::ListModules(const std::string& pattern) {
    std::vector<std::string> rv;
    for (const auto& [module, deps] : module_deps_) {
        // Attempt to match both the canonical module name and the module filename.
        if (!fnmatch(pattern.c_str(), module.c_str(), 0)) {
            rv.emplace_back(module);
        } else if (!fnmatch(pattern.c_str(), android::base::Basename(deps[0]).c_str(), 0)) {
            rv.emplace_back(deps[0]);
        }
    }
    return rv;
}

bool Modprobe::GetAllDependencies(const std::string& module,
                                  std::vector<std::string>* pre_dependencies,
                                  std::vector<std::string>* dependencies,
                                  std::vector<std::string>* post_dependencies) {
    std::string canonical_name = MakeCanonical(module);
    if (pre_dependencies) {
        pre_dependencies->clear();
        for (const auto& [it_module, it_softdep] : module_pre_softdep_) {
            if (canonical_name == it_module) {
                pre_dependencies->emplace_back(it_softdep);
            }
        }
    }
    if (dependencies) {
        dependencies->clear();
        auto hard_deps = GetDependencies(canonical_name);
        if (hard_deps.empty()) {
            return false;
        }
        for (auto dep = hard_deps.rbegin(); dep != hard_deps.rend(); dep++) {
            dependencies->emplace_back(*dep);
        }
    }
    if (post_dependencies) {
        for (const auto& [it_module, it_softdep] : module_post_softdep_) {
            if (canonical_name == it_module) {
                post_dependencies->emplace_back(it_softdep);
            }
        }
    }
    return true;
}
