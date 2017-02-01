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

TEST(MemoryLocalTest, read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  MemoryLocal local;

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(local.Read(reinterpret_cast<uint64_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }

  memset(src.data(), 0x23, 512);
  ASSERT_TRUE(local.Read(reinterpret_cast<uint64_t>(src.data()), dst.data(), 1024));
  ASSERT_EQ(0, memcmp(src.data(), dst.data(), 1024));
  for (size_t i = 0; i < 512; i++) {
    ASSERT_EQ(0x23U, dst[i]);
  }
  for (size_t i = 512; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]);
  }
}

TEST(MemoryLocalTest, read_string) {
  std::string name("string_in_memory");

  MemoryLocal local;

  std::vector<uint8_t> dst(1024);
  std::string dst_name;
  ASSERT_TRUE(local.ReadString(reinterpret_cast<uint64_t>(name.c_str()), &dst_name));
  ASSERT_EQ("string_in_memory", dst_name);

  ASSERT_TRUE(local.ReadString(reinterpret_cast<uint64_t>(&name[7]), &dst_name));
  ASSERT_EQ("in_memory", dst_name);

  ASSERT_TRUE(local.ReadString(reinterpret_cast<uint64_t>(&name[7]), &dst_name, 10));
  ASSERT_EQ("in_memory", dst_name);

  ASSERT_FALSE(local.ReadString(reinterpret_cast<uint64_t>(&name[7]), &dst_name, 9));
}

TEST(MemoryLocalTest, read_illegal) {
  MemoryLocal local;

  std::vector<uint8_t> dst(100);
  ASSERT_FALSE(local.Read(0, dst.data(), 1));
  ASSERT_FALSE(local.Read(0, dst.data(), 100));
}
