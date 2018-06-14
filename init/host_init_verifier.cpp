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
#include <pwd.h>
#include <stdio.h>

#include <iostream>
#include <string>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "host_import_parser.h"
#include "host_init_stubs.h"
#include "parser.h"
#include "result.h"
#include "service.h"

#define EXCLUDE_FS_CONFIG_STRUCTURES
#include "generated_android_ids.h"

using namespace std::literals;

using android::base::ParseInt;
using android::base::ReadFileToString;
using android::base::Split;

static std::string out_dir;

static std::vector<std::pair<std::string, int>> GetVendorPasswd() {
    std::string passwd;
    if (!ReadFileToString(out_dir + "/vendor/etc/passwd", &passwd)) {
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

static Result<Success> do_stub(const BuiltinArguments& args) {
    return Success();
}

#include "generated_stub_builtin_function_map.h"

int main(int argc, char** argv) {
    android::base::InitLogging(argv, &android::base::StdioLogger);
    android::base::SetMinimumLogSeverity(android::base::ERROR);
    if (argc != 3) {
        LOG(ERROR) << "Usage: " << argv[0] << " <out directory> <properties>";
        return -1;
    }

    out_dir = argv[1];

    auto properties = Split(argv[2], ",");
    for (const auto& property : properties) {
        auto split_property = Split(property, "=");
        if (split_property.size() != 2) {
            continue;
        }
        property_set(split_property[0], split_property[1]);
    }

    const BuiltinFunctionMap function_map;
    Action::set_function_map(&function_map);
    ActionManager& am = ActionManager::GetInstance();
    ServiceList& sl = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&sl, nullptr));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));
    parser.AddSectionParser("import", std::make_unique<HostImportParser>(out_dir, &parser));

    if (!parser.ParseConfig(argv[1] + "/root/init.rc"s)) {
        LOG(ERROR) << "Failed to find root init.rc script";
        return -1;
    }
    if (parser.parse_error_count() > 0) {
        LOG(ERROR) << "Init script parsing failed with " << parser.parse_error_count() << " errors";
        return -1;
    }
    return 0;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    android::init::main(argc, argv);
}
