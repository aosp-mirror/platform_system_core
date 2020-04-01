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

#include <chrono>

#include <android-base/properties.h>

using android::base::GetProperty;
using android::base::SetProperty;
using android::base::WaitForProperty;
using namespace std::literals;

TEST(init, oneshot_on) {
    if (getuid() != 0) {
        GTEST_SKIP() << "Skipping test, must be run as root.";
        return;
    }

    // Bootanim shouldn't be running once the device has booted.
    ASSERT_EQ("stopped", GetProperty("init.svc.bootanim", ""));

    SetProperty("ctl.oneshot_off", "bootanim");
    SetProperty("ctl.start", "bootanim");

    // Bootanim exits quickly when the device is fully booted, so check that it goes back to the
    // 'restarting' state that non-oneshot services enter once they've restarted.
    EXPECT_TRUE(WaitForProperty("init.svc.bootanim", "restarting", 10s));

    SetProperty("ctl.oneshot_on", "bootanim");
    SetProperty("ctl.start", "bootanim");

    // Now that oneshot is enabled again, bootanim should transition into the 'stopped' state.
    EXPECT_TRUE(WaitForProperty("init.svc.bootanim", "stopped", 10s));
}
