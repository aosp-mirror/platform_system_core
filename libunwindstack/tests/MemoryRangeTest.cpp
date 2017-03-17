/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include <stdint.h>
#include <string.h>

#include <vector>

#include <gtest/gtest.h>

#include "Memory.h"

#include "MemoryFake.h"

class MemoryRangeTest : public ::testing::Test {
 protected:
  void SetUp() override {
    memory_ = new MemoryFake;
  }

  MemoryFake* memory_;
};

TEST_F(MemoryRangeTest, read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);
  memory_->SetMemory(9001, src);

  MemoryRange range(memory_, 9001, 9001 + src.size());

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(range.Read(0, dst.data(), src.size()));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }
}

TEST_F(MemoryRangeTest, read_near_limit) {
  std::vector<uint8_t> src(4096);
  memset(src.data(), 0x4c, 4096);
  memory_->SetMemory(1000, src);

  MemoryRange range(memory_, 1000, 2024);

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(range.Read(1020, dst.data(), 4));
  for (size_t i = 0; i < 4; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }

  // Verify that reads outside of the range will fail.
  ASSERT_FALSE(range.Read(1020, dst.data(), 5));
  ASSERT_FALSE(range.Read(1024, dst.data(), 1));
  ASSERT_FALSE(range.Read(1024, dst.data(), 1024));
}

TEST_F(MemoryRangeTest, read_string_past_end) {
  std::string name("0123456789");
  memory_->SetMemory(0, name);

  // Verify a read past the range fails.
  MemoryRange range(memory_, 0, 5);
  std::string dst_name;
  ASSERT_FALSE(range.ReadString(0, &dst_name));
}

TEST_F(MemoryRangeTest, read_string_to_end) {
  std::string name("0123456789");
  memory_->SetMemory(30, name);

  // Verify the range going to the end of the string works.
  MemoryRange range(memory_, 30, 30 + name.size() + 1);
  std::string dst_name;
  ASSERT_TRUE(range.ReadString(0, &dst_name));
  ASSERT_EQ("0123456789", dst_name);
}

TEST_F(MemoryRangeTest, read_string_fencepost) {
  std::string name("0123456789");
  memory_->SetMemory(10, name);

  // Verify the range set to one byte less than the end of the string fails.
  MemoryRange range(memory_, 10, 10 + name.size());
  std::string dst_name;
  ASSERT_FALSE(range.ReadString(0, &dst_name));
}
