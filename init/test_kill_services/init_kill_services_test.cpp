/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <android-base/properties.h>

#include <iostream>

using ::android::base::GetProperty;
using ::android::base::SetProperty;

void ExpectKillingServiceRecovers(const std::string& service_name) {
    const std::string status_prop = "init.svc." + service_name;
    const std::string pid_prop = "init.svc_debug_pid." + service_name;

    const std::string initial_pid = GetProperty(pid_prop, "");

    ASSERT_EQ("running", GetProperty(status_prop, "")) << status_prop;
    ASSERT_NE("", initial_pid) << pid_prop;

    EXPECT_EQ(0, system(("kill -9 " + initial_pid).c_str()));

    constexpr size_t kMaxWaitMilliseconds = 10000;
    constexpr size_t kRetryWaitMilliseconds = 100;

    constexpr size_t kRetryTimes = kMaxWaitMilliseconds / kRetryWaitMilliseconds;

    for (size_t retry = 0; retry < kRetryTimes; retry++) {
        const std::string& pid = GetProperty(pid_prop, "");
        if (pid != initial_pid && pid != "") break;
        usleep(kRetryWaitMilliseconds * 1000);
    }

    // svc_debug_pid is set after svc property
    EXPECT_EQ("running", GetProperty(status_prop, ""));
}

class InitKillServicesTest : public ::testing::TestWithParam<std::string> {};

TEST_P(InitKillServicesTest, KillCriticalProcesses) {
    ExpectKillingServiceRecovers(GetParam());

    // Ensure that init is still responding
    EXPECT_TRUE(SetProperty("test.death.test", "asdf"));
    EXPECT_EQ(GetProperty("test.death.test", ""), "asdf");
    EXPECT_TRUE(SetProperty("test.death.test", ""));
}

static inline std::string PrintName(const testing::TestParamInfo<std::string>& info) {
    return info.param;
}

INSTANTIATE_TEST_CASE_P(DeathTest, InitKillServicesTest,
                        ::testing::Values("lmkd", "ueventd", "hwservicemanager", "servicemanager"),
                        PrintName);
