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

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <chrono>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <libdm/dm_table.h>
#include <libdm/loop_control.h>

#include "test_util.h"

using namespace android;
using namespace android::base;
using namespace android::dm;
using namespace std;
using namespace std::chrono_literals;

/*
 * This test aims at making the library crash, so these functions are not
 * really useful.
 * Keeping them here for future use.
 */
template <class T, class C>
void ASSERT_EQ(const T& /*a*/, const C& /*b*/) {
    // if (a != b) {}
}

template <class T>
void ASSERT_FALSE(const T& /*a*/) {
    // if (a) {}
}

template <class T, class C>
void ASSERT_GE(const T& /*a*/, const C& /*b*/) {
    // if (a < b) {}
}

template <class T, class C>
void ASSERT_NE(const T& /*a*/, const C& /*b*/) {
    // if (a == b) {}
}

template <class T>
void ASSERT_TRUE(const T& /*a*/) {
    // if (!a) {}
}

template <class T, class C>
void EXPECT_EQ(const T& a, const C& b) {
    ASSERT_EQ(a, b);
}

template <class T>
void EXPECT_TRUE(const T& a) {
    ASSERT_TRUE(a);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uint64_t val[6];

    if (size != sizeof(val)) {
        return 0;
    }

    memcpy(&val, &data[0], sizeof(*val));

    unique_fd tmp1(CreateTempFile("file_1", 4096));
    ASSERT_GE(tmp1, 0);
    unique_fd tmp2(CreateTempFile("file_2", 4096));
    ASSERT_GE(tmp2, 0);

    LoopDevice loop_a(tmp1, 10s);
    ASSERT_TRUE(loop_a.valid());
    LoopDevice loop_b(tmp2, 10s);
    ASSERT_TRUE(loop_b.valid());

    // Define a 2-sector device, with each sector mapping to the first sector
    // of one of our loop devices.
    DmTable table;
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(val[0], val[1], loop_a.device(), val[2]));
    ASSERT_TRUE(table.Emplace<DmTargetLinear>(val[3], val[4], loop_b.device(), val[5]));
    ASSERT_TRUE(table.valid());
    ASSERT_EQ(2u, table.num_sectors());

    TempDevice dev("libdm-test-dm-linear", table);
    ASSERT_TRUE(dev.valid());
    ASSERT_FALSE(dev.path().empty());

    auto& dm = DeviceMapper::Instance();

    dev_t dev_number;
    ASSERT_TRUE(dm.GetDeviceNumber(dev.name(), &dev_number));
    ASSERT_NE(dev_number, 0);

    std::string dev_string;
    ASSERT_TRUE(dm.GetDeviceString(dev.name(), &dev_string));
    ASSERT_FALSE(dev_string.empty());

    // Test GetTableStatus.
    vector<DeviceMapper::TargetInfo> targets;
    ASSERT_TRUE(dm.GetTableStatus(dev.name(), &targets));
    ASSERT_EQ(targets.size(), 2);
    EXPECT_EQ(strcmp(targets[0].spec.target_type, "linear"), 0);
    EXPECT_TRUE(targets[0].data.empty());
    EXPECT_EQ(targets[0].spec.sector_start, 0);
    EXPECT_EQ(targets[0].spec.length, 1);
    EXPECT_EQ(strcmp(targets[1].spec.target_type, "linear"), 0);
    EXPECT_TRUE(targets[1].data.empty());
    EXPECT_EQ(targets[1].spec.sector_start, 1);
    EXPECT_EQ(targets[1].spec.length, 1);

    // Test GetTargetType().
    EXPECT_EQ(DeviceMapper::GetTargetType(targets[0].spec), std::string{"linear"});
    EXPECT_EQ(DeviceMapper::GetTargetType(targets[1].spec), std::string{"linear"});

    // Normally the TestDevice destructor would delete this, but at least one
    // test should ensure that device deletion works.
    ASSERT_TRUE(dev.Destroy());

    return 0;
}
