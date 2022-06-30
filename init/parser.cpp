/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "parser.h"

#include <dirent.h>

#include <map>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>

#include "tokenizer.h"
#include "util.h"

namespace android {
namespace init {

Parser::Parser() {}

void Parser::AddSectionParser(const std::string& name, std::unique_ptr<SectionParser> parser) {
    section_parsers_[name] = std::move(parser);
}

void Parser::AddSingleLineParser(const std::string& prefix, LineCallback callback) {
    line_callbacks_.emplace_back(prefix, std::move(callback));
}

void Parser::ParseData(const std::string& filename, std::string* data) {
    data->push_back('\n');
    data->push_back('\0');

    parse_state state;
    state.line = 0;
    state.ptr = data->data();
    state.nexttoken = 0;

    SectionParser* section_parser = nullptr;
    int section_start_line = -1;
    std::vector<std::string> args;

    // If we encounter a bad section start, there is no valid parser object to parse the subsequent
    // sections, so we must suppress errors until the next valid section is found.
    bool bad_section_found = false;

    auto end_section = [&] {
        bad_section_found = false;
        if (section_parser == nullptr) return;

        if (auto result = section_parser->EndSection(); !result.ok()) {
            parse_error_count_++;
            LOG(ERROR) << filename << ": " << section_start_line << ": " << result.error();
        }

        section_parser = nullptr;
        section_start_line = -1;
    };

    for (;;) {
        switch (next_token(&state)) {
            case T_EOF:
                end_section();

                for (const auto& [section_name, section_parser] : section_parsers_) {
                    section_parser->EndFile();
                }

                return;
            case T_NEWLINE: {
                state.line++;
                if (args.empty()) break;
                // If we have a line matching a prefix we recognize, call its callback and unset any
                // current section parsers.  This is meant for /sys/ and /dev/ line entries for
                // uevent.
                auto line_callback = std::find_if(
                    line_callbacks_.begin(), line_callbacks_.end(),
                    [&args](const auto& c) { return android::base::StartsWith(args[0], c.first); });
                if (line_callback != line_callbacks_.end()) {
                    end_section();

                    if (auto result = line_callback->second(std::move(args)); !result.ok()) {
                        parse_error_count_++;
                        LOG(ERROR) << filename << ": " << state.line << ": " << result.error();
                    }
                } else if (section_parsers_.count(args[0])) {
                    end_section();
                    section_parser = section_parsers_[args[0]].get();
                    section_start_line = state.line;
                    if (auto result =
                                section_parser->ParseSection(std::move(args), filename, state.line);
                        !result.ok()) {
                        parse_error_count_++;
                        LOG(ERROR) << filename << ": " << state.line << ": " << result.error();
                        section_parser = nullptr;
                        bad_section_found = true;
                    }
                } else if (section_parser) {
                    if (auto result = section_parser->ParseLineSection(std::move(args), state.line);
                        !result.ok()) {
                        parse_error_count_++;
                        LOG(ERROR) << filename << ": " << state.line << ": " << result.error();
                    }
                } else if (!bad_section_found) {
                    parse_error_count_++;
                    LOG(ERROR) << filename << ": " << state.line
                               << ": Invalid section keyword found";
                }
                args.clear();
                break;
            }
            case T_TEXT:
                args.emplace_back(state.text);
                break;
        }
    }
}

bool Parser::ParseConfigFileInsecure(const std::string& path) {
    std::string config_contents;
    if (!android::base::ReadFileToString(path, &config_contents)) {
        return false;
    }

    ParseData(path, &config_contents);
    return true;
}

bool Parser::ParseConfigFile(const std::string& path) {
    LOG(INFO) << "Parsing file " << path << "...";
    android::base::Timer t;
    auto config_contents = ReadFile(path);
    if (!config_contents.ok()) {
        LOG(INFO) << "Unable to read config file '" << path << "': " << config_contents.error();
        return false;
    }

    ParseData(path, &config_contents.value());

    LOG(VERBOSE) << "(Parsing " << path << " took " << t << ".)";
    return true;
}

std::vector<std::string> Parser::FilterVersionedConfigs(const std::vector<std::string>& configs,
                                                        int active_sdk) {
    std::vector<std::string> filtered_configs;

    std::map<std::string, std::pair<std::string, int>> script_map;
    for (const auto& c : configs) {
        int sdk = 0;
        const std::vector<std::string> parts = android::base::Split(c, ".");
        std::string base;
        if (parts.size() < 2) {
            continue;
        }

        // parts[size()-1], aka the suffix, should be "rc" or "#rc"
        // any other pattern gets discarded

        const auto& suffix = parts[parts.size() - 1];
        if (suffix == "rc") {
            sdk = 0;
        } else {
            char trailer[9] = {0};
            int r = sscanf(suffix.c_str(), "%d%8s", &sdk, trailer);
            if (r != 2) {
                continue;
            }
            if (strlen(trailer) > 2 || strcmp(trailer, "rc") != 0) {
                continue;
            }
        }

        if (sdk < 0 || sdk > active_sdk) {
            continue;
        }

        base = parts[0];
        for (unsigned int i = 1; i < parts.size() - 1; i++) {
            base = base + "." + parts[i];
        }

        // is this preferred over what we already have
        auto it = script_map.find(base);
        if (it == script_map.end() || it->second.second < sdk) {
            script_map[base] = std::make_pair(c, sdk);
        }
    }

    for (const auto& m : script_map) {
        filtered_configs.push_back(m.second.first);
    }
    return filtered_configs;
}

bool Parser::ParseConfigDir(const std::string& path) {
    LOG(INFO) << "Parsing directory " << path << "...";
    std::unique_ptr<DIR, decltype(&closedir)> config_dir(opendir(path.c_str()), closedir);
    if (!config_dir) {
        PLOG(INFO) << "Could not import directory '" << path << "'";
        return false;
    }
    dirent* current_file;
    std::vector<std::string> files;
    while ((current_file = readdir(config_dir.get()))) {
        // Ignore directories and only process regular files.
        if (current_file->d_type == DT_REG) {
            std::string current_path =
                android::base::StringPrintf("%s/%s", path.c_str(), current_file->d_name);
            files.emplace_back(current_path);
        }
    }
    // Sort first so we load files in a consistent order (bug 31996208)
    std::sort(files.begin(), files.end());
    for (const auto& file : files) {
        if (!ParseConfigFile(file)) {
            LOG(ERROR) << "could not import file '" << file << "'";
        }
    }
    return true;
}

bool Parser::ParseConfig(const std::string& path) {
    if (is_dir(path.c_str())) {
        return ParseConfigDir(path);
    }
    return ParseConfigFile(path);
}

}  // namespace init
}  // namespace android
