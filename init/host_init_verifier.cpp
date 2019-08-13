//
// Copyright (C) 2018 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include <errno.h>
#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>

#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "check_builtins.h"
#include "host_import_parser.h"
#include "host_init_stubs.h"
#include "interface_utils.h"
#include "parser.h"
#include "result.h"
#include "service.h"
#include "service_list.h"
#include "service_parser.h"

#define EXCLUDE_FS_CONFIG_STRUCTURES
#include "generated_android_ids.h"

using namespace std::literals;

using android::base::ParseInt;
using android::base::ReadFileToString;
using android::base::Split;

static std::vector<std::string> passwd_files;

static std::vector<std::pair<std::string, int>> GetVendorPasswd(const std::string& passwd_file) {
    std::string passwd;
    if (!ReadFileToString(passwd_file, &passwd)) {
        return {};
    }

    std::vector<std::pair<std::string, int>> result;
    auto passwd_lines = Split(passwd, "\n");
    for (const auto& line : passwd_lines) {
        auto split_line = Split(line, ":");
        if (split_line.size() < 3) {
            continue;
        }
        int uid = 0;
        if (!ParseInt(split_line[2], &uid)) {
            continue;
        }
        result.emplace_back(split_line[0], uid);
    }
    return result;
}

static std::vector<std::pair<std::string, int>> GetVendorPasswd() {
    std::vector<std::pair<std::string, int>> result;
    for (const auto& passwd_file : passwd_files) {
        auto individual_result = GetVendorPasswd(passwd_file);
        std::move(individual_result.begin(), individual_result.end(),
                  std::back_insert_iterator(result));
    }
    return result;
}

passwd* getpwnam(const char* login) {  // NOLINT: implementing bad function.
    // This isn't thread safe, but that's okay for our purposes.
    static char static_name[32] = "";
    static char static_dir[32] = "/";
    static char static_shell[32] = "/system/bin/sh";
    static passwd static_passwd = {
        .pw_name = static_name,
        .pw_dir = static_dir,
        .pw_shell = static_shell,
        .pw_uid = 0,
        .pw_gid = 0,
    };

    for (size_t n = 0; n < android_id_count; ++n) {
        if (!strcmp(android_ids[n].name, login)) {
            snprintf(static_name, sizeof(static_name), "%s", android_ids[n].name);
            static_passwd.pw_uid = android_ids[n].aid;
            static_passwd.pw_gid = android_ids[n].aid;
            return &static_passwd;
        }
    }

    static const auto vendor_passwd = GetVendorPasswd();

    for (const auto& [name, uid] : vendor_passwd) {
        if (name == login) {
            snprintf(static_name, sizeof(static_name), "%s", name.c_str());
            static_passwd.pw_uid = uid;
            static_passwd.pw_gid = uid;
            return &static_passwd;
        }
    }

    unsigned int oem_uid;
    if (sscanf(login, "oem_%u", &oem_uid) == 1) {
        snprintf(static_name, sizeof(static_name), "%s", login);
        static_passwd.pw_uid = oem_uid;
        static_passwd.pw_gid = oem_uid;
        return &static_passwd;
    }

    errno = ENOENT;
    return nullptr;
}

namespace android {
namespace init {

static Result<void> check_stub(const BuiltinArguments& args) {
    return {};
}

#include "generated_stub_builtin_function_map.h"

void PrintUsage() {
    std::cout << "usage: host_init_verifier [-p FILE] -i FILE <init rc file>\n"
                 "\n"
                 "Tests an init script for correctness\n"
                 "\n"
                 "-p FILE\tSearch this passwd file for users and groups\n"
                 "-i FILE\tParse this JSON file for the HIDL interface inheritance hierarchy\n"
              << std::endl;
}

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StdioLogger);
    android::base::SetMinimumLogSeverity(android::base::ERROR);

    std::string interface_inheritance_hierarchy_file;

    while (true) {
        static const struct option long_options[] = {
                {"help", no_argument, nullptr, 'h'},
                {nullptr, 0, nullptr, 0},
        };

        int arg = getopt_long(argc, argv, "p:i:", long_options, nullptr);

        if (arg == -1) {
            break;
        }

        switch (arg) {
            case 'h':
                PrintUsage();
                return EXIT_FAILURE;
            case 'p':
                passwd_files.emplace_back(optarg);
                break;
            case 'i':
                interface_inheritance_hierarchy_file = optarg;
                break;
            default:
                std::cerr << "getprop: getopt returned invalid result: " << arg << std::endl;
                return EXIT_FAILURE;
        }
    }

    argc -= optind;
    argv += optind;

    if (argc != 1 || interface_inheritance_hierarchy_file.empty()) {
        PrintUsage();
        return EXIT_FAILURE;
    }

    auto interface_inheritance_hierarchy_map =
            ReadInterfaceInheritanceHierarchy(interface_inheritance_hierarchy_file);
    if (!interface_inheritance_hierarchy_map) {
        LOG(ERROR) << interface_inheritance_hierarchy_map.error();
        return EXIT_FAILURE;
    }
    SetKnownInterfaces(*interface_inheritance_hierarchy_map);

    const BuiltinFunctionMap& function_map = GetBuiltinFunctionMap();
    Action::set_function_map(&function_map);
    ActionManager& am = ActionManager::GetInstance();
    ServiceList& sl = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(
                                               &sl, nullptr, *interface_inheritance_hierarchy_map));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));
    parser.AddSectionParser("import", std::make_unique<HostImportParser>());

    if (!parser.ParseConfigFileInsecure(*argv)) {
        LOG(ERROR) << "Failed to open init rc script '" << *argv << "'";
        return EXIT_FAILURE;
    }
    size_t failures = parser.parse_error_count() + am.CheckAllCommands() + sl.CheckAllCommands();
    if (failures > 0) {
        LOG(ERROR) << "Failed to parse init script '" << *argv << "' with " << failures
                   << " errors";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    return android::init::main(argc, argv);
}
