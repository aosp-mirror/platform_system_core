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
#include <map>
#include <set>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <generated_android_ids.h>
#include <hidl/metadata.h>
#include <property_info_parser/property_info_parser.h>
#include <property_info_serializer/property_info_serializer.h>

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

using namespace std::literals;

using android::base::EndsWith;
using android::base::ParseInt;
using android::base::ReadFileToString;
using android::base::Split;
using android::properties::ParsePropertyInfoFile;
using android::properties::PropertyInfoEntry;

static std::vector<std::string> passwd_files;

// NOTE: Keep this in sync with the order used by init.cpp LoadBootScripts()
static const std::vector<std::string> partition_search_order =
        std::vector<std::string>({"system", "system_ext", "odm", "vendor", "product"});

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
        .pw_uid = 0,
        .pw_gid = 0,
        .pw_shell = static_shell,
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

void PrintUsage() {
    fprintf(stdout, R"(usage: host_init_verifier [options]

Tests init script(s) for correctness.

Generic options:
  -p FILE                     Search this passwd file for users and groups.
  --property_contexts=FILE    Use this file for property_contexts.

Single script mode options:
  [init rc file]              Positional argument; test this init script.

Multiple script mode options:
  --out_system=DIR            Path to the output product directory for the system partition.
  --out_system_ext=DIR        Path to the output product directory for the system_ext partition.
  --out_odm=DIR               Path to the output product directory for the odm partition.
  --out_vendor=DIR            Path to the output product directory for the vendor partition.
  --out_product=DIR           Path to the output product directory for the product partition.
)");
}

Result<InterfaceInheritanceHierarchyMap> ReadInterfaceInheritanceHierarchy() {
    InterfaceInheritanceHierarchyMap result;
    for (const HidlInterfaceMetadata& iface : HidlInterfaceMetadata::all()) {
        std::set<FQName> inherited_interfaces;
        for (const std::string& intf : iface.inherited) {
            FQName fqname;
            if (!fqname.setTo(intf)) {
                return Error() << "Unable to parse interface '" << intf << "'";
            }
            inherited_interfaces.insert(fqname);
        }
        FQName fqname;
        if (!fqname.setTo(iface.name)) {
            return Error() << "Unable to parse interface '" << iface.name << "'";
        }
        result[fqname] = inherited_interfaces;
    }

    return result;
}

void HandlePropertyContexts(const std::string& filename,
                            std::vector<PropertyInfoEntry>* property_infos) {
    auto file_contents = std::string();
    if (!ReadFileToString(filename, &file_contents)) {
        PLOG(ERROR) << "Could not read properties from '" << filename << "'";
        exit(EXIT_FAILURE);
    }

    auto errors = std::vector<std::string>{};
    ParsePropertyInfoFile(file_contents, true, property_infos, &errors);
    for (const auto& error : errors) {
        LOG(ERROR) << "Could not read line from '" << filename << "': " << error;
    }
    if (!errors.empty()) {
        exit(EXIT_FAILURE);
    }
}

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StdioLogger);
    android::base::SetMinimumLogSeverity(android::base::ERROR);

    auto property_infos = std::vector<PropertyInfoEntry>();
    std::map<std::string, std::string> partition_map;

    while (true) {
        static const char kPropertyContexts[] = "property-contexts=";
        static const struct option long_options[] = {
                {"help", no_argument, nullptr, 'h'},
                {kPropertyContexts, required_argument, nullptr, 0},
                {"out_system", required_argument, nullptr, 0},
                {"out_system_ext", required_argument, nullptr, 0},
                {"out_odm", required_argument, nullptr, 0},
                {"out_vendor", required_argument, nullptr, 0},
                {"out_product", required_argument, nullptr, 0},
                {nullptr, 0, nullptr, 0},
        };

        int option_index;
        int arg = getopt_long(argc, argv, "p:", long_options, &option_index);

        if (arg == -1) {
            break;
        }

        switch (arg) {
            case 0:
                if (long_options[option_index].name == kPropertyContexts) {
                    HandlePropertyContexts(optarg, &property_infos);
                }
                for (const auto& p : partition_search_order) {
                    if (long_options[option_index].name == "out_" + p) {
                        if (partition_map.find(p) != partition_map.end()) {
                            PrintUsage();
                            return EXIT_FAILURE;
                        }
                        partition_map[p] =
                                EndsWith(optarg, "/") ? optarg : std::string(optarg) + "/";
                    }
                }
                break;
            case 'h':
                PrintUsage();
                return EXIT_FAILURE;
            case 'p':
                passwd_files.emplace_back(optarg);
                break;
            default:
                std::cerr << "getprop: getopt returned invalid result: " << arg << std::endl;
                return EXIT_FAILURE;
        }
    }

    argc -= optind;
    argv += optind;

    // If provided, use the partition map to check multiple init rc files.
    // Otherwise, check a single init rc file.
    if ((!partition_map.empty() && argc != 0) || (partition_map.empty() && argc != 1)) {
        PrintUsage();
        return EXIT_FAILURE;
    }

    auto interface_inheritance_hierarchy_map = ReadInterfaceInheritanceHierarchy();
    if (!interface_inheritance_hierarchy_map.ok()) {
        LOG(ERROR) << interface_inheritance_hierarchy_map.error();
        return EXIT_FAILURE;
    }
    SetKnownInterfaces(*interface_inheritance_hierarchy_map);

    if (auto result = InitializeHostPropertyInfoArea(property_infos); !result.ok()) {
        LOG(ERROR) << result.error();
        return EXIT_FAILURE;
    }

    if (!partition_map.empty()) {
        std::vector<std::string> vendor_prefixes;
        for (const auto& partition : {"vendor", "odm"}) {
            if (partition_map.find(partition) != partition_map.end()) {
                vendor_prefixes.push_back(partition_map.at(partition));
            }
        }
        InitializeHostSubcontext(vendor_prefixes);
    }

    const BuiltinFunctionMap& function_map = GetBuiltinFunctionMap();
    Action::set_function_map(&function_map);
    ActionManager& am = ActionManager::GetInstance();
    ServiceList& sl = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(&sl, GetSubcontext(),
                                                            *interface_inheritance_hierarchy_map));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, GetSubcontext()));
    parser.AddSectionParser("import", std::make_unique<HostImportParser>());

    if (!partition_map.empty()) {
        for (const auto& p : partition_search_order) {
            if (partition_map.find(p) != partition_map.end()) {
                parser.ParseConfig(partition_map.at(p) + "etc/init");
            }
        }
    } else {
        if (!parser.ParseConfigFileInsecure(*argv, true /* follow_symlinks */)) {
          // Follow symlinks as inputs during build execution in Bazel's
          // execution root are symlinks, unlike Soong or Make.
            LOG(ERROR) << "Failed to open init rc script '" << *argv << "'";
            return EXIT_FAILURE;
        }
    }
    size_t failures = parser.parse_error_count() + am.CheckAllCommands() + sl.CheckAllCommands();
    if (failures > 0) {
        LOG(ERROR) << "Failed to parse init scripts with " << failures << " error(s).";
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    return android::init::main(argc, argv);
}
