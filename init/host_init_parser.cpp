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

#include <android-base/logging.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "parser.h"
#include "result.h"
#include "service.h"

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
    android::base::InitLogging(argv, &android::base::StderrLogger);
    if (argc != 2) {
        LOG(ERROR) << "Usage: " << argv[0] << " <init file to parse>";
        return -1;
    }
    const BuiltinFunctionMap function_map;
    Action::set_function_map(&function_map);
    ActionManager& am = ActionManager::GetInstance();
    ServiceList& sl = ServiceList::GetInstance();
    Parser parser;
    parser.AddSectionParser("service", std::make_unique<ServiceParser>(&sl, nullptr));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));

    size_t num_errors = 0;
    if (!parser.ParseConfig(argv[1], &num_errors)) {
        LOG(ERROR) << "Failed to find script";
        return -1;
    }
    if (num_errors > 0) {
        LOG(ERROR) << "Parse failed with " << num_errors << " errors";
        return -1;
    }
    LOG(INFO) << "Parse success!";
    return 0;
}

}  // namespace init
}  // namespace android

int main(int argc, char** argv) {
    android::init::main(argc, argv);
}
