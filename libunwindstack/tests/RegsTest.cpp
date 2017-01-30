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

#include <gtest/gtest.h>

#include "Regs.h"

class RegsTest : public ::testing::Test {};

TEST_F(RegsTest, regs32) {
  Regs32 regs32(10, 20, 30);

  ASSERT_EQ(10U, regs32.pc_reg());
  ASSERT_EQ(20U, regs32.sp_reg());
  ASSERT_EQ(30U, regs32.total_regs());

  uint32_t* raw = reinterpret_cast<uint32_t*>(regs32.raw_data());
  for (size_t i = 0; i < 30; i++) {
    raw[i] = 0xf0000000 + i;
  }

  ASSERT_EQ(0xf000000aU, regs32.pc());
  ASSERT_EQ(0xf0000014U, regs32.sp());

  ASSERT_EQ(0xf0000001U, regs32[1]);
  regs32[1] = 10;
  ASSERT_EQ(10U, regs32[1]);

  ASSERT_EQ(0xf000001dU, regs32[29]);
}

TEST_F(RegsTest, regs64) {
  Regs64 regs64(10, 20, 30);

  ASSERT_EQ(10U, regs64.pc_reg());
  ASSERT_EQ(20U, regs64.sp_reg());
  ASSERT_EQ(30U, regs64.total_regs());

  uint64_t* raw = reinterpret_cast<uint64_t*>(regs64.raw_data());
  for (size_t i = 0; i < 30; i++) {
    raw[i] = 0xf123456780000000UL + i;
  }

  ASSERT_EQ(0xf12345678000000aUL, regs64.pc());
  ASSERT_EQ(0xf123456780000014UL, regs64.sp());

  ASSERT_EQ(0xf123456780000008U, regs64[8]);
  regs64[8] = 10;
  ASSERT_EQ(10U, regs64[8]);

  ASSERT_EQ(0xf12345678000001dU, regs64[29]);
}
