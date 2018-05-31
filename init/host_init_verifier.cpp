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

#include <pwd.h>

#include <iostream>
#include <string>

#include <android-base/logging.h>
#include <android-base/strings.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "host_import_parser.h"
#include "host_init_stubs.h"
#include "parser.h"
#include "result.h"
#include "service.h"

using namespace std::literals;

using android::base::Split;

// The host passwd file won't have the Android entries, so we fake success here.
passwd* getpwnam(const char* login) {  // NOLINT: implementing bad function.
    char dummy_buf[] = "dummy";
    static passwd dummy_passwd = {
        .pw_name = dummy_buf,
        .pw_dir = dummy_buf,
        .pw_shell = dummy_buf,
        .pw_uid = 123,
        .pw_gid = 123,
    };
    return &dummy_passwd;
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
    parser.AddSectionParser("import", std::make_unique<HostImportParser>(argv[1], &parser));

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
