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

#include <sysexits.h>
#include <unistd.h>

#include <iostream>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android/hardware/health/2.1/IHealth.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <health/utils.h>

#include "healthd_mode_charger_hidl.h"

using android::hardware::Return;
using android::hardware::health::InitHealthdConfig;
using std::string_literals::operator""s;
using testing::_;
using testing::Invoke;
using testing::NiceMock;
using testing::StrEq;
using testing::Test;

namespace android {

// A replacement to ASSERT_* to be used in a forked process. When the condition is not met,
// print a gtest message, then exit abnormally.
class ChildAssertHelper : public std::stringstream {
  public:
    ChildAssertHelper(bool res, const char* expr, const char* file, int line) : res_(res) {
        (*this) << file << ":" << line << ": `" << expr << "` evaluates to false\n";
    }
    ~ChildAssertHelper() {
        EXPECT_TRUE(res_) << str();
        if (!res_) exit(EX_SOFTWARE);
    }

  private:
    bool res_;
    DISALLOW_COPY_AND_ASSIGN(ChildAssertHelper);
};
#define CHILD_ASSERT_TRUE(expr) ChildAssertHelper(expr, #expr, __FILE__, __LINE__)

// Run |test_body| in a chroot jail in a forked process. |subdir| is a sub-directory in testdata.
// Within |test_body|,
// - non-fatal errors may be reported using EXPECT_* macro as usual.
// - fatal errors must be reported using CHILD_ASSERT_TRUE macro. ASSERT_* must not be used.
void ForkTest(const std::string& subdir, const std::function<void(void)>& test_body) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0) << "Fork fails: " << strerror(errno);
    if (pid == 0) {
        // child
        CHILD_ASSERT_TRUE(
                chroot((android::base::GetExecutableDirectory() + "/" + subdir).c_str()) != -1)
                << "Failed to chroot to " << subdir << ": " << strerror(errno);
        test_body();
        // EXPECT_* macros may set the HasFailure bit without calling exit(). Set exit status
        // accordingly.
        exit(::testing::Test::HasFailure() ? EX_SOFTWARE : EX_OK);
    }
    // parent
    int status;
    ASSERT_NE(-1, waitpid(pid, &status, 0)) << "waitpid() fails: " << strerror(errno);
    ASSERT_TRUE(WIFEXITED(status)) << "Test fails, waitpid() returns " << status;
    ASSERT_EQ(EX_OK, WEXITSTATUS(status)) << "Test fails, child process returns " << status;
}

class MockHealth : public android::hardware::health::V2_1::IHealth {
    MOCK_METHOD(Return<::android::hardware::health::V2_0::Result>, registerCallback,
                (const sp<::android::hardware::health::V2_0::IHealthInfoCallback>& callback));
    MOCK_METHOD(Return<::android::hardware::health::V2_0::Result>, unregisterCallback,
                (const sp<::android::hardware::health::V2_0::IHealthInfoCallback>& callback));
    MOCK_METHOD(Return<::android::hardware::health::V2_0::Result>, update, ());
    MOCK_METHOD(Return<void>, getChargeCounter, (getChargeCounter_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getCurrentNow, (getCurrentNow_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getCurrentAverage, (getCurrentAverage_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getCapacity, (getCapacity_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getEnergyCounter, (getEnergyCounter_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getChargeStatus, (getChargeStatus_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getStorageInfo, (getStorageInfo_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getDiskStats, (getDiskStats_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getHealthInfo, (getHealthInfo_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getHealthConfig, (getHealthConfig_cb _hidl_cb));
    MOCK_METHOD(Return<void>, getHealthInfo_2_1, (getHealthInfo_2_1_cb _hidl_cb));
    MOCK_METHOD(Return<void>, shouldKeepScreenOn, (shouldKeepScreenOn_cb _hidl_cb));
};

class TestCharger : public ChargerHidl {
  public:
    // Inherit constructor.
    using ChargerHidl::ChargerHidl;
    // Expose protected functions to be used in tests.
    void Init(struct healthd_config* config) override { ChargerHidl::Init(config); }
    MOCK_METHOD(int, CreateDisplaySurface, (const std::string& name, GRSurface** surface));
    MOCK_METHOD(int, CreateMultiDisplaySurface,
                (const std::string& name, int* frames, int* fps, GRSurface*** surface));
};

// Intentionally leak TestCharger instance to avoid calling ~HealthLoop() because ~HealthLoop()
// should never be called. But still verify expected calls upon destruction.
class VerifiedTestCharger {
  public:
    VerifiedTestCharger(TestCharger* charger) : charger_(charger) {
        testing::Mock::AllowLeak(charger_);
    }
    TestCharger& operator*() { return *charger_; }
    TestCharger* operator->() { return charger_; }
    ~VerifiedTestCharger() { testing::Mock::VerifyAndClearExpectations(charger_); }

  private:
    TestCharger* charger_;
};

// Do not use SetUp and TearDown of a test suite, as they will be invoked in the parent process, not
// the child process. In particular, if the test suite contains mocks, they will not be verified in
// the child process. Instead, create mocks within closures in each tests.
void ExpectChargerResAt(const std::string& root) {
    sp<NiceMock<MockHealth>> health(new NiceMock<MockHealth>());
    VerifiedTestCharger charger(new NiceMock<TestCharger>(health));

    // Only one frame in all testdata/**/animation.txt
    GRSurface* multi[] = {nullptr};

    EXPECT_CALL(*charger, CreateDisplaySurface(StrEq(root + "charger/battery_fail.png"), _))
            .WillRepeatedly(Invoke([](const auto&, GRSurface** surface) {
                *surface = nullptr;
                return 0;
            }));
    EXPECT_CALL(*charger,
                CreateMultiDisplaySurface(StrEq(root + "charger/battery_scale.png"), _, _, _))
            .WillRepeatedly(Invoke([&](const auto&, int* frames, int* fps, GRSurface*** surface) {
                *frames = arraysize(multi);
                *fps = 60;  // Unused fps value
                *surface = multi;
                return 0;
            }));
    struct healthd_config healthd_config;
    InitHealthdConfig(&healthd_config);
    charger->Init(&healthd_config);
};

// Test that if resources does not exist in /res or in /product/etc/res, load from /system.
TEST(ChargerLoadAnimationRes, Empty) {
    ForkTest("empty", std::bind(&ExpectChargerResAt, "/system/etc/res/images/"));
}

// Test loading everything from /res
TEST(ChargerLoadAnimationRes, Legacy) {
    ForkTest("legacy", std::bind(&ExpectChargerResAt, "/res/images/"));
}

// Test loading animation text from /res but images from /system if images does not exist under
// /res.
TEST(ChargerLoadAnimationRes, LegacyTextSystemImages) {
    ForkTest("legacy_text_system_images",
             std::bind(&ExpectChargerResAt, "/system/etc/res/images/"));
}

// Test loading everything from /product
TEST(ChargerLoadAnimationRes, Product) {
    ForkTest("product", std::bind(&ExpectChargerResAt, "/product/etc/res/images/"));
}

}  // namespace android
