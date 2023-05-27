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
#include <fstream>
#include <iostream>
#include <memory>
#include <unordered_map>
#include "android-base/strings.h"
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
