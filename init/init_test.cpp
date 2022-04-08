/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <functional>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <gtest/gtest.h>

#include "action.h"
#include "action_manager.h"
#include "action_parser.h"
#include "builtin_arguments.h"
#include "builtins.h"
#include "import_parser.h"
#include "keyword_map.h"
#include "parser.h"
#include "service.h"
#include "service_list.h"
#include "service_parser.h"
#include "util.h"

using android::base::GetIntProperty;

namespace android {
namespace init {

using ActionManagerCommand = std::function<void(ActionManager&)>;

void TestInit(const std::string& init_script_file, const BuiltinFunctionMap& test_function_map,
              const std::vector<ActionManagerCommand>& commands, ServiceList* service_list) {
    ActionManager am;

    Action::set_function_map(&test_function_map);

    Parser parser;
    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(service_list, nullptr, std::nullopt));
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    ASSERT_TRUE(parser.ParseConfig(init_script_file));

    for (const auto& command : commands) {
        command(am);
    }

    while (am.HasMoreCommands()) {
        am.ExecuteOneCommand();
    }
}

void TestInitText(const std::string& init_script, const BuiltinFunctionMap& test_function_map,
                  const std::vector<ActionManagerCommand>& commands, ServiceList* service_list) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));
    TestInit(tf.path, test_function_map, commands, service_list);
}

TEST(init, SimpleEventTrigger) {
    bool expect_true = false;
    std::string init_script =
        R"init(
on boot
pass_test
)init";

    auto do_pass_test = [&expect_true](const BuiltinArguments&) {
        expect_true = true;
        return Result<void>{};
    };
    BuiltinFunctionMap test_function_map = {
            {"pass_test", {0, 0, {false, do_pass_test}}},
    };

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    ServiceList service_list;
    TestInitText(init_script, test_function_map, commands, &service_list);

    EXPECT_TRUE(expect_true);
}

TEST(init, WrongEventTrigger) {
    std::string init_script =
            R"init(
on boot:
pass_test
)init";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));

    ActionManager am;

    Parser parser;
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am, nullptr));

    ASSERT_TRUE(parser.ParseConfig(tf.path));
    ASSERT_EQ(1u, parser.parse_error_count());
}

TEST(init, EventTriggerOrder) {
    std::string init_script =
        R"init(
on boot
execute_first

on boot && property:ro.hardware=*
execute_second

on boot
execute_third

)init";

    int num_executed = 0;
    auto do_execute_first = [&num_executed](const BuiltinArguments&) {
        EXPECT_EQ(0, num_executed++);
        return Result<void>{};
    };
    auto do_execute_second = [&num_executed](const BuiltinArguments&) {
        EXPECT_EQ(1, num_executed++);
        return Result<void>{};
    };
    auto do_execute_third = [&num_executed](const BuiltinArguments&) {
        EXPECT_EQ(2, num_executed++);
        return Result<void>{};
    };

    BuiltinFunctionMap test_function_map = {
            {"execute_first", {0, 0, {false, do_execute_first}}},
            {"execute_second", {0, 0, {false, do_execute_second}}},
            {"execute_third", {0, 0, {false, do_execute_third}}},
    };

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    ServiceList service_list;
    TestInitText(init_script, test_function_map, commands, &service_list);
}

TEST(init, OverrideService) {
    std::string init_script = R"init(
service A something
    class first

service A something
    class second
    override

)init";

    ServiceList service_list;
    TestInitText(init_script, BuiltinFunctionMap(), {}, &service_list);
    ASSERT_EQ(1, std::distance(service_list.begin(), service_list.end()));

    auto service = service_list.begin()->get();
    ASSERT_NE(nullptr, service);
    EXPECT_EQ(std::set<std::string>({"second"}), service->classnames());
    EXPECT_EQ("A", service->name());
    EXPECT_TRUE(service->is_override());
}

TEST(init, EventTriggerOrderMultipleFiles) {
    // 6 total files, which should have their triggers executed in the following order:
    // 1: start - original script parsed
    // 2: first_import - immediately imported by first_script
    // 3: dir_a - file named 'a.rc' in dir; dir is imported after first_import
    // 4: a_import - file imported by dir_a
    // 5: dir_b - file named 'b.rc' in dir
    // 6: last_import - imported after dir is imported

    TemporaryFile first_import;
    ASSERT_TRUE(first_import.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 2", first_import.fd));

    TemporaryFile dir_a_import;
    ASSERT_TRUE(dir_a_import.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 4", dir_a_import.fd));

    TemporaryFile last_import;
    ASSERT_TRUE(last_import.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd("on boot\nexecute 6", last_import.fd));

    TemporaryDir dir;
    // clang-format off
    std::string dir_a_script = "import " + std::string(dir_a_import.path) + "\n"
                               "on boot\n"
                               "execute 3";
    // clang-format on
    // WriteFile() ensures the right mode is set
    ASSERT_RESULT_OK(WriteFile(std::string(dir.path) + "/a.rc", dir_a_script));

    ASSERT_RESULT_OK(WriteFile(std::string(dir.path) + "/b.rc", "on boot\nexecute 5"));

    // clang-format off
    std::string start_script = "import " + std::string(first_import.path) + "\n"
                               "import " + std::string(dir.path) + "\n"
                               "import " + std::string(last_import.path) + "\n"
                               "on boot\n"
                               "execute 1";
    // clang-format on
    TemporaryFile start;
    ASSERT_TRUE(android::base::WriteStringToFd(start_script, start.fd));

    int num_executed = 0;
    auto execute_command = [&num_executed](const BuiltinArguments& args) {
        EXPECT_EQ(2U, args.size());
        EXPECT_EQ(++num_executed, std::stoi(args[1]));
        return Result<void>{};
    };

    BuiltinFunctionMap test_function_map = {
            {"execute", {1, 1, {false, execute_command}}},
    };

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    ServiceList service_list;

    TestInit(start.path, test_function_map, commands, &service_list);

    EXPECT_EQ(6, num_executed);
}

TEST(init, RejectsCriticalAndOneshotService) {
    if (GetIntProperty("ro.product.first_api_level", 10000) < 30) {
        GTEST_SKIP() << "Test only valid for devices launching with R or later";
    }

    std::string init_script =
            R"init(
service A something
  class first
  critical
  oneshot
)init";

    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));

    ServiceList service_list;
    Parser parser;
    parser.AddSectionParser("service",
                            std::make_unique<ServiceParser>(&service_list, nullptr, std::nullopt));

    ASSERT_TRUE(parser.ParseConfig(tf.path));
    ASSERT_EQ(1u, parser.parse_error_count());
}

}  // namespace init
}  // namespace android

int SubcontextTestChildMain(int, char**);
int FirmwareTestChildMain(int, char**);

int main(int argc, char** argv) {
    if (argc > 1 && !strcmp(argv[1], "subcontext")) {
        return SubcontextTestChildMain(argc, argv);
    }

    if (argc > 1 && !strcmp(argv[1], "firmware")) {
        return FirmwareTestChildMain(argc, argv);
    }

    testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
