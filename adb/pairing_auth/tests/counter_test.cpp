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

#include <adb/pairing/counter.h>

namespace adb {
namespace pairing {

static constexpr size_t kTestCounterSize = 13;
static const uint8_t kZeroes[64] = {0};

TEST(AdbCounterTest, size_match) {
    Counter<kTestCounterSize> counter;
    ASSERT_EQ(kTestCounterSize, counter.size());
}

TEST(AdbCounterTest, Increase) {
    Counter<kTestCounterSize> counter;
    memset(counter.data(), 0, counter.size());
    counter.Increase();
    EXPECT_EQ(1, counter[counter.size() - 1]);
    EXPECT_EQ(0, memcmp(counter.data(), kZeroes, counter.size() - 1));
}

TEST(AdbCounterTest, rollover_first_byte) {
    Counter<kTestCounterSize> counter;
    memset(counter.data(), 0, counter.size());
    counter[counter.size() - 1] = 0xFF;
    counter.Increase();
    EXPECT_EQ(0, counter[counter.size() - 1]);
    EXPECT_EQ(1, counter[counter.size() - 2]);
    EXPECT_EQ(0, memcmp(counter.data(), kZeroes, counter.size() - 2));
}

TEST(AdbCounterTest, multiple_rollover) {
    Counter<kTestCounterSize> counter;
    memset(counter.data(), 0xFF, counter.size());
    memset(counter.data(), 0, counter.size() - 3);
    counter.Increase();
    EXPECT_EQ(0, counter[counter.size() - 5]);
    EXPECT_EQ(1, counter[counter.size() - 4]);
    EXPECT_EQ(0, counter[counter.size() - 3]);
    EXPECT_EQ(0, counter[counter.size() - 2]);
    EXPECT_EQ(0, counter[counter.size() - 1]);
}

TEST(AdbCounterTest, full_rollover) {
    Counter<kTestCounterSize> counter;
    memset(counter.data(), 0xFF, counter.size());
    counter.Increase();
    EXPECT_EQ(0, memcmp(counter.data(), kZeroes, counter.size()));
}

}  // namespace pairing
}  // namespace adb
