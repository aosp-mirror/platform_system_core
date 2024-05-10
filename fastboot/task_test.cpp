//
// Copyright (C) 2023 The Android Open Source Project
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

#include "task.h"
#include "fastboot.h"
#include "fastboot_driver_mock.h"

#include <gtest/gtest.h>
#include <iostream>
#include <memory>
#include "android-base/strings.h"
#include "gmock/gmock.h"

using android::base::Split;
using testing::_;

class ParseTest : public ::testing ::Test {
  protected:
    void SetUp() override {
        fp = std::make_unique<FlashingPlan>();
        fp->slot_override = "b";
        fp->secondary_slot = "a";
        fp->wants_wipe = false;
    }
    void TearDown() override {}

    std::unique_ptr<FlashingPlan> fp;

  private:
};

static std::vector<std::unique_ptr<Task>> collectTasks(FlashingPlan* fp,
                                                       const std::vector<std::string>& commands) {
    std::vector<std::vector<std::string>> vec_commands;
    for (auto& command : commands) {
        vec_commands.emplace_back(android::base::Split(command, " "));
    }
    std::vector<std::unique_ptr<Task>> tasks;
    for (auto& command : vec_commands) {
        tasks.emplace_back(ParseFastbootInfoLine(fp, command));
    }
    return tasks;
}

std::unique_ptr<Task> ParseCommand(FlashingPlan* fp, std::string command) {
    std::vector<std::string> vec_command = android::base::Split(command, " ");
    return ParseFastbootInfoLine(fp, vec_command);
}

// tests if tasks_a is a superset of tasks_b. Used for checking to ensure all partitions flashed
// from hardcoded image list is also flashed in new fastboot-info.txt
static bool compareTaskList(std::vector<std::unique_ptr<Task>>& tasks_a,
                            std::vector<std::unique_ptr<Task>>& tasks_b) {
    std::set<std::string> list;
    for (auto& task : tasks_a) {
        list.insert(task->ToString());
    }
    for (auto& task : tasks_b) {
        if (list.find(task->ToString()) == list.end()) {
            std::cout << "ERROR: " << task->ToString()
                      << " not found in task list created by fastboot-info.txt";
            return false;
        }
    }
    return true;
}

static std::string tasksToString(std::vector<std::unique_ptr<Task>>& tasks) {
    std::string output;
    for (auto& task : tasks) {
        output.append(task->ToString());
        output.append("\n");
    }
    return output;
}

TEST_F(ParseTest, CorrectFlashTaskFormed) {
    std::vector<std::string> commands = {"flash dtbo", "flash --slot-other system system_other.img",
                                         "flash system", "flash --apply-vbmeta vbmeta"};

    std::vector<std::unique_ptr<Task>> tasks = collectTasks(fp.get(), commands);

    std::vector<std::vector<std::string>> expected_values{
            {"dtbo", "dtbo_b", "b", "dtbo.img"},
            {"system", "system_a", "a", "system_other.img"},
            {"system", "system_b", "b", "system.img"},
            {"vbmeta", "vbmeta_b", "b", "vbmeta.img"}

    };

    for (auto& task : tasks) {
        ASSERT_TRUE(task != nullptr);
    }

    for (size_t i = 0; i < tasks.size(); i++) {
        auto task = tasks[i]->AsFlashTask();
        ASSERT_TRUE(task != nullptr);
        ASSERT_EQ(task->GetPartition(), expected_values[i][0]);
        ASSERT_EQ(task->GetPartitionAndSlot(), expected_values[i][1]);
        ASSERT_EQ(task->GetSlot(), expected_values[i][2]);
        ASSERT_EQ(task->GetImageName(), expected_values[i][3]);
    }
}

TEST_F(ParseTest, VersionCheckCorrect) {
    std::vector<std::string> correct_versions = {"version 1", "version 22", "version 5",
                                                 "version 17"};

    std::vector<std::string> bad_versions = {"version",         "version .01",    "version x1",
                                             "version 1.0.1",   "version 1.",     "s 1.0",
                                             "version 1.0 2.0", "version 100.00", "version 1 2"};

    for (auto& version : correct_versions) {
        ASSERT_TRUE(CheckFastbootInfoRequirements(android::base::Split(version, " "), 26))
                << version;
    }

    // returning False for failing version check
    for (auto& version : correct_versions) {
        ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(version, " "), 0))
                << version;
    }
    // returning False for bad format
    for (auto& version : bad_versions) {
        ASSERT_FALSE(CheckFastbootInfoRequirements(android::base::Split(version, " "), 100))
                << version;
    }
}

TEST_F(ParseTest, BadFastbootInput) {
    ASSERT_EQ(ParseCommand(fp.get(), "flash"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "flash --slot-other --apply-vbmeta"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "flash --apply-vbmeta"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "if-wipe"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "if-wipe flash"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "wipe dtbo"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "update-super dtbo"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "flash system system.img system"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "reboot bootloader fastboot"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(),
                           "flash --slot-other --apply-vbmeta system system_other.img system"),
              nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "erase"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "erase dtbo dtbo"), nullptr);
    ASSERT_EQ(ParseCommand(fp.get(), "wipe this"), nullptr);
}

TEST_F(ParseTest, CorrectTaskFormed) {
    std::vector<std::string> commands = {"flash dtbo", "flash --slot-other system system_other.img",
                                         "reboot bootloader", "update-super", "erase cache"};
    std::vector<std::unique_ptr<Task>> tasks = collectTasks(fp.get(), commands);

    ASSERT_TRUE(tasks[0]->AsFlashTask());
    ASSERT_TRUE(tasks[0]->AsFlashTask());
    ASSERT_TRUE(tasks[1]->AsFlashTask());
    ASSERT_TRUE(tasks[2]->AsRebootTask());
    ASSERT_TRUE(tasks[3]->AsUpdateSuperTask());
    ASSERT_TRUE(tasks[4]->AsWipeTask());
}

TEST_F(ParseTest, CorrectDriverCalls) {
    fastboot::MockFastbootDriver fb;
    fp->fb = &fb;

    EXPECT_CALL(fb, RebootTo(_, _, _)).Times(1);
    EXPECT_CALL(fb, Reboot(_, _)).Times(1);
    EXPECT_CALL(fb, WaitForDisconnect()).Times(2);

    std::vector<std::string> commands = {"reboot bootloader", "reboot"};
    std::vector<std::unique_ptr<Task>> tasks = collectTasks(fp.get(), commands);

    for (auto& task : tasks) {
        task->Run();
    }
}

TEST_F(ParseTest, CorrectTaskLists) {
    if (!get_android_product_out()) {
        GTEST_SKIP();
    }

    fp->source.reset(new LocalImageSource);
    fp->sparse_limit = std::numeric_limits<int64_t>::max();

    fastboot::MockFastbootDriver fb;
    fp->fb = &fb;
    fp->should_optimize_flash_super = false;

    ON_CALL(fb, GetVar("super-partition-name", _, _))
            .WillByDefault(testing::Return(fastboot::BAD_ARG));

    FlashAllTool tool(fp.get());

    fp->should_use_fastboot_info = false;
    auto hardcoded_tasks = tool.CollectTasks();
    fp->should_use_fastboot_info = true;
    auto fastboot_info_tasks = tool.CollectTasks();

    auto is_non_flash_task = [](const auto& task) -> bool {
        return task->AsFlashTask() == nullptr;
    };

    // remove non flash tasks for testing purposes
    hardcoded_tasks.erase(
            std::remove_if(hardcoded_tasks.begin(), hardcoded_tasks.end(), is_non_flash_task),
            hardcoded_tasks.end());
    fastboot_info_tasks.erase(std::remove_if(fastboot_info_tasks.begin(), fastboot_info_tasks.end(),
                                             is_non_flash_task),
                              fastboot_info_tasks.end());

    if (!compareTaskList(fastboot_info_tasks, hardcoded_tasks)) {
        std::cout << "\n\n---Hardcoded Task List---\n"
                  << tasksToString(hardcoded_tasks) << "\n---Fastboot-Info Task List---\n"
                  << tasksToString(fastboot_info_tasks);
    }

    ASSERT_TRUE(compareTaskList(fastboot_info_tasks, hardcoded_tasks));

    ASSERT_TRUE(fastboot_info_tasks.size() >= hardcoded_tasks.size())
            << "size of fastboot-info task list: " << fastboot_info_tasks.size()
            << " size of hardcoded task list: " << hardcoded_tasks.size();
}
TEST_F(ParseTest, IsDynamicPartitiontest) {
    if (!get_android_product_out()) {
        GTEST_SKIP();
    }

    fp->source.reset(new LocalImageSource);

    fastboot::MockFastbootDriver fb;
    fp->fb = &fb;
    fp->should_optimize_flash_super = true;
    fp->should_use_fastboot_info = true;

    std::vector<std::pair<std::string, bool>> test_cases = {
            {"flash boot", false},
            {"flash init_boot", false},
            {"flash --apply-vbmeta vbmeta", false},
            {"flash product", true},
            {"flash system", true},
            {"flash --slot-other system system_other.img", true},
    };
    for (auto& test : test_cases) {
        std::unique_ptr<Task> task =
                ParseFastbootInfoLine(fp.get(), android::base::Tokenize(test.first, " "));
        auto flash_task = task->AsFlashTask();
        ASSERT_FALSE(flash_task == nullptr);
        ASSERT_EQ(FlashTask::IsDynamicPartition(fp->source.get(), flash_task), test.second);
    }
}

TEST_F(ParseTest, CanOptimizeTest) {
    if (!get_android_product_out()) {
        GTEST_SKIP();
    }

    fp->source.reset(new LocalImageSource);
    fp->sparse_limit = std::numeric_limits<int64_t>::max();

    fastboot::MockFastbootDriver fb;
    fp->fb = &fb;
    fp->should_optimize_flash_super = false;
    fp->should_use_fastboot_info = true;

    std::vector<std::pair<std::vector<std::string>, bool>> patternmatchtest = {
            {{"flash boot", "flash init_boot", "flash vendor_boot", "reboot fastboot",
              "update-super", "flash product", "flash system", "flash system_ext", "flash odm",
              "if-wipe erase userdata"},
             true},
            {{"flash boot", "flash init_boot", "flash vendor_boot", "reboot fastboot",
              "update-super", "flash product", "flash system", "flash system_ext", "flash odm",
              "if-wipe erase userdata"},
             true},
            {{"flash boot", "flash init_boot", "flash vendor_boot", "reboot fastboot",
              "flash product", "flash system", "flash system_ext", "flash odm",
              "if-wipe erase userdata"},
             false},
            {{"flash boot", "flash init_boot", "flash vendor_boot", "update-super", "flash product",
              "flash system", "flash system_ext", "flash odm", "if-wipe erase userdata"},
             false},
    };

    auto remove_if_callback = [&](const auto& task) -> bool { return !!task->AsResizeTask(); };

    for (auto& test : patternmatchtest) {
        std::vector<std::unique_ptr<Task>> tasks = ParseFastbootInfo(fp.get(), test.first);
        tasks.erase(std::remove_if(tasks.begin(), tasks.end(), remove_if_callback), tasks.end());
        ASSERT_EQ(OptimizedFlashSuperTask::CanOptimize(fp->source.get(), tasks), test.second);
    }
}

// Note: this test is exclusively testing that optimized flash super pattern matches a given task
// list and is able to optimized based on a correct sequence of tasks
TEST_F(ParseTest, OptimizedFlashSuperPatternMatchTest) {
    if (!get_android_product_out()) {
        GTEST_SKIP();
    }

    fp->source.reset(new LocalImageSource);
    fp->sparse_limit = std::numeric_limits<int64_t>::max();

    fastboot::MockFastbootDriver fb;
    fp->fb = &fb;
    fp->should_optimize_flash_super = true;
    fp->should_use_fastboot_info = true;

    ON_CALL(fb, GetVar("super-partition-name", _, _))
            .WillByDefault(testing::Return(fastboot::BAD_ARG));

    ON_CALL(fb, GetVar("slot-count", _, _))
            .WillByDefault(testing::DoAll(testing::SetArgPointee<1>("2"),
                                          testing::Return(fastboot::SUCCESS)));

    ON_CALL(fb, GetVar("partition-size:super", _, _))
            .WillByDefault(testing::DoAll(testing::SetArgPointee<1>("1000"),
                                          testing::Return(fastboot::SUCCESS)));

    std::vector<std::pair<std::vector<std::string>, bool>> patternmatchtest = {
            {{"flash boot", "flash init_boot", "flash vendor_boot", "reboot fastboot",
              "update-super", "flash product", "flash system", "flash system_ext", "flash odm",
              "if-wipe erase userdata"},
             true},
            {{"flash boot", "flash init_boot", "flash vendor_boot", "reboot fastboot",
              "update-super", "flash product", "flash system", "flash system_ext", "flash odm",
              "if-wipe erase userdata"},
             true},
            {{"flash boot", "flash init_boot", "flash vendor_boot", "reboot fastboot",
              "flash product", "flash system", "flash system_ext", "flash odm",
              "if-wipe erase userdata"},
             false},
            {{"flash boot", "flash init_boot", "flash vendor_boot", "update-super", "flash product",
              "flash system", "flash system_ext", "flash odm", "if-wipe erase userdata"},
             false},
    };

    for (auto& test : patternmatchtest) {
        std::vector<std::unique_ptr<Task>> tasks = ParseFastbootInfo(fp.get(), test.first);
        // Check to make sure we have an optimized flash super task && no more dynamic partition
        // flashing tasks
        auto&& IsOptimized = [](const FlashingPlan* fp,
                                const std::vector<std::unique_ptr<Task>>& tasks) {
            bool contains_optimized_task = false;
            for (auto& task : tasks) {
                if (task->AsOptimizedFlashSuperTask()) {
                    contains_optimized_task = true;
                }
                if (auto flash_task = task->AsFlashTask()) {
                    if (FlashTask::IsDynamicPartition(fp->source.get(), flash_task)) {
                        return false;
                    }
                }
            }
            return contains_optimized_task;
        };
        ASSERT_EQ(IsOptimized(fp.get(), tasks), test.second);
    }
}
