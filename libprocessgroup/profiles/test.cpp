/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <string>

#include <android-base/file.h>
#include <gmock/gmock.h>
#include <jsonpb/json_schema_test.h>

#include "cgroups.pb.h"
#include "task_profiles.pb.h"

using namespace ::android::jsonpb;
using ::android::base::GetExecutableDirectory;
using ::testing::MatchesRegex;

namespace android {
namespace profiles {

template <typename T>
JsonSchemaTestConfigFactory MakeTestParam(const std::string& path) {
    return jsonpb::MakeTestParam<T>(GetExecutableDirectory() + path);
}

TEST(LibProcessgroupProto, EmptyMode) {
    EXPECT_EQ(0, strtoul("", nullptr, 8))
            << "Empty mode string cannot be silently converted to 0; this should not happen";
}

class CgroupsTest : public JsonSchemaTest {
  public:
    void SetUp() override {
        JsonSchemaTest::SetUp();
        cgroups_ = static_cast<Cgroups*>(message());
    }
    Cgroups* cgroups_;
};

TEST_P(CgroupsTest, CgroupRequiredFields) {
    for (int i = 0; i < cgroups_->cgroups_size(); ++i) {
        auto&& cgroup = cgroups_->cgroups(i);
        EXPECT_FALSE(cgroup.controller().empty())
                << "No controller name for cgroup #" << i << " in " << file_path_;
        EXPECT_FALSE(cgroup.path().empty()) << "No path for cgroup #" << i << " in " << file_path_;
    }
}

TEST_P(CgroupsTest, Cgroup2RequiredFields) {
    if (cgroups_->has_cgroups2()) {
        EXPECT_FALSE(cgroups_->cgroups2().path().empty())
                << "No path for cgroup2 in " << file_path_;
    }
}

// "Mode" field must be in the format of "0xxx".
static constexpr const char* REGEX_MODE = "(0[0-7]{3})?";
TEST_P(CgroupsTest, CgroupMode) {
    for (int i = 0; i < cgroups_->cgroups_size(); ++i) {
        EXPECT_THAT(cgroups_->cgroups(i).mode(), MatchesRegex(REGEX_MODE))
                << "For cgroup controller #" << i << " in " << file_path_;
    }
}

TEST_P(CgroupsTest, Cgroup2Mode) {
    EXPECT_THAT(cgroups_->cgroups2().mode(), MatchesRegex(REGEX_MODE))
            << "For cgroups2 in " << file_path_;
}

class TaskProfilesTest : public JsonSchemaTest {
  public:
    void SetUp() override {
        JsonSchemaTest::SetUp();
        task_profiles_ = static_cast<TaskProfiles*>(message());
    }
    TaskProfiles* task_profiles_;
};

TEST_P(TaskProfilesTest, AttributeRequiredFields) {
    for (int i = 0; i < task_profiles_->attributes_size(); ++i) {
        auto&& attribute = task_profiles_->attributes(i);
        EXPECT_FALSE(attribute.name().empty())
                << "No name for attribute #" << i << " in " << file_path_;
        EXPECT_FALSE(attribute.controller().empty())
                << "No controller for attribute #" << i << " in " << file_path_;
        EXPECT_FALSE(attribute.file().empty())
                << "No file for attribute #" << i << " in " << file_path_;
    }
}

TEST_P(TaskProfilesTest, ProfileRequiredFields) {
    for (int profile_idx = 0; profile_idx < task_profiles_->profiles_size(); ++profile_idx) {
        auto&& profile = task_profiles_->profiles(profile_idx);
        EXPECT_FALSE(profile.name().empty())
                << "No name for profile #" << profile_idx << " in " << file_path_;
        for (int action_idx = 0; action_idx < profile.actions_size(); ++action_idx) {
            auto&& action = profile.actions(action_idx);
            EXPECT_FALSE(action.name().empty())
                    << "No name for profiles[" << profile_idx << "].actions[" << action_idx
                    << "] in " << file_path_;
        }
    }
}

// Test suite instantiations

INSTANTIATE_TEST_SUITE_P(, JsonSchemaTest,
                         ::testing::Values(MakeTestParam<Cgroups>("/cgroups.json"),
                                           MakeTestParam<Cgroups>("/cgroups.recovery.json"),
                                           MakeTestParam<TaskProfiles>("/task_profiles.json")));
INSTANTIATE_TEST_SUITE_P(, CgroupsTest,
                         ::testing::Values(MakeTestParam<Cgroups>("/cgroups.json"),
                                           MakeTestParam<Cgroups>("/cgroups.recovery.json")));
INSTANTIATE_TEST_SUITE_P(, TaskProfilesTest,
                         ::testing::Values(MakeTestParam<TaskProfiles>("/task_profiles.json")));

}  // namespace profiles
}  // namespace android

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
