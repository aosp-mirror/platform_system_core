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

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <hidl/ServiceManagement.h>

#include <iostream>

using ::android::base::GetProperty;
using ::android::base::SetProperty;
using ::android::base::WaitForProperty;
using ::android::hardware::isHidlSupported;
using std::literals::chrono_literals::operator""s;

void ExpectKillingServiceRecovers(const std::string& service_name) {
    if (!isHidlSupported() && service_name == "hwservicemanager") {
        GTEST_SKIP() << "No HIDL support on device so hwservicemanager will not be running";
    }
    LOG(INFO) << "before we say hi to " << service_name << ", I can't have apexd around!";

    // b/280514080 - servicemanager will restart apexd, and apexd will restart the
    // system when crashed. This is fine as the device recovers, but it causes
    // flakes in this test.
    ASSERT_TRUE(WaitForProperty("init.svc.apexd", "stopped", 120s))
            << (system("cat /dev/binderfs/binder_logs/state"), "apexd won't stop");

    LOG(INFO) << "hello " << service_name << "!";
    const std::string status_prop = "init.svc." + service_name;
    const std::string pid_prop = "init.svc_debug_pid." + service_name;

    const std::string initial_pid = GetProperty(pid_prop, "");

    ASSERT_EQ("running", GetProperty(status_prop, "")) << status_prop;
    ASSERT_NE("", initial_pid) << pid_prop;

    LOG(INFO) << "okay, now goodbye " << service_name;
    EXPECT_EQ(0, system(("kill -9 " + initial_pid).c_str()));

    constexpr size_t kMaxWaitMilliseconds = 10000;
    constexpr size_t kRetryWaitMilliseconds = 100;

    constexpr size_t kRetryTimes = kMaxWaitMilliseconds / kRetryWaitMilliseconds;

    for (size_t retry = 0; retry < kRetryTimes; retry++) {
        const std::string& pid = GetProperty(pid_prop, "");
        if (pid != initial_pid && pid != "") break;
        LOG(INFO) << "I said goodbye " << service_name << "!";
        usleep(kRetryWaitMilliseconds * 1000);
    }

    LOG(INFO) << "are you still there " << service_name << "?";

    // svc_debug_pid is set after svc property
    EXPECT_EQ("running", GetProperty(status_prop, ""));

    LOG(INFO) << "I'm done with " << service_name;
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

INSTANTIATE_TEST_CASE_P(
        DeathTest, InitKillServicesTest,
        ::testing::Values(
                // clang-format off

// TODO: we may want a more automatic way of testing this for services based on some
// criteria (e.g. not disabled), but for now adding core services one at a time

// BEGIN INTERNAL ONLY MERGE GUARD (add things here if internal only, move down later)
// END INTERNAL ONLY MERGE GUARD

// BEGIN AOSP ONLY (add things here if adding to AOSP)
    "lmkd",
    "ueventd",
    "hwservicemanager",
    "servicemanager",
    "system_suspend"
// END AOSP ONLY

                // clang-format on
                ),
        PrintName);
