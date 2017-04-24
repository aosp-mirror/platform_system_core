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
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

#include "action.h"
#include "builtins.h"
#include "import_parser.h"
#include "init_parser.h"
#include "keyword_map.h"
#include "util.h"

class TestFunctionMap : public KeywordMap<BuiltinFunction> {
  public:
    // Helper for argument-less functions
    using BuiltinFunctionNoArgs = std::function<void(void)>;
    void Add(const std::string& name, const BuiltinFunctionNoArgs function) {
        Add(name, 0, 0, [function](const std::vector<std::string>&) {
            function();
            return 0;
        });
    }

    void Add(const std::string& name, std::size_t min_parameters, std::size_t max_parameters,
             const BuiltinFunction function) {
        builtin_functions_[name] = make_tuple(min_parameters, max_parameters, function);
    }

  private:
    Map builtin_functions_ = {};

    const Map& map() const override { return builtin_functions_; }
};

using ActionManagerCommand = std::function<void(ActionManager&)>;

void TestInit(const std::string& init_script_file, const TestFunctionMap& test_function_map,
              const std::vector<ActionManagerCommand>& commands) {
    ActionManager am;

    Action::set_function_map(&test_function_map);

    Parser parser;
    parser.AddSectionParser("on", std::make_unique<ActionParser>(&am));
    parser.AddSectionParser("import", std::make_unique<ImportParser>(&parser));

    ASSERT_TRUE(parser.ParseConfig(init_script_file));

    for (const auto& command : commands) {
        command(am);
    }

    while (am.HasMoreCommands()) {
        am.ExecuteOneCommand();
    }
}

void TestInitText(const std::string& init_script, const TestFunctionMap& test_function_map,
                  const std::vector<ActionManagerCommand>& commands) {
    TemporaryFile tf;
    ASSERT_TRUE(tf.fd != -1);
    ASSERT_TRUE(android::base::WriteStringToFd(init_script, tf.fd));
    TestInit(tf.path, test_function_map, commands);
}

TEST(init, SimpleEventTrigger) {
    bool expect_true = false;
    std::string init_script =
        R"init(
on boot
pass_test
)init";

    TestFunctionMap test_function_map;
    test_function_map.Add("pass_test", [&expect_true]() { expect_true = true; });

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    TestInitText(init_script, test_function_map, commands);

    EXPECT_TRUE(expect_true);
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
    TestFunctionMap test_function_map;
    test_function_map.Add("execute_first", [&num_executed]() { EXPECT_EQ(0, num_executed++); });
    test_function_map.Add("execute_second", [&num_executed]() { EXPECT_EQ(1, num_executed++); });
    test_function_map.Add("execute_third", [&num_executed]() { EXPECT_EQ(2, num_executed++); });

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    TestInitText(init_script, test_function_map, commands);
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
    // write_file() ensures the right mode is set
    ASSERT_TRUE(write_file(std::string(dir.path) + "/a.rc", dir_a_script));

    ASSERT_TRUE(write_file(std::string(dir.path) + "/b.rc", "on boot\nexecute 5"));

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
    auto execute_command = [&num_executed](const std::vector<std::string>& args) {
        EXPECT_EQ(2U, args.size());
        EXPECT_EQ(++num_executed, std::stoi(args[1]));
        return 0;
    };

    TestFunctionMap test_function_map;
    test_function_map.Add("execute", 1, 1, execute_command);

    ActionManagerCommand trigger_boot = [](ActionManager& am) { am.QueueEventTrigger("boot"); };
    std::vector<ActionManagerCommand> commands{trigger_boot};

    TestInit(start.path, test_function_map, commands);

    EXPECT_EQ(6, num_executed);
}
