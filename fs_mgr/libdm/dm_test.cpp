/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <map>

#include <gtest/gtest.h>
#include <libdm/dm.h>

using namespace std;
using namespace android::dm;

TEST(libdm, HasMinimumTargets) {
    DeviceMapper& dm = DeviceMapper::Instance();
    vector<DmTargetTypeInfo> targets;
    ASSERT_TRUE(dm.GetAvailableTargets(&targets));

    map<string, DmTargetTypeInfo> by_name;
    for (const auto& target : targets) {
        by_name[target.name()] = target;
    }

    auto iter = by_name.find("linear");
    EXPECT_NE(iter, by_name.end());
}
