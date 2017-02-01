/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <elf.h>

#include <gtest/gtest.h>

#include <vector>

#include "ElfInterfaceArm.h"
#include "Machine.h"
#include "Regs.h"

#include "MemoryFake.h"

class ElfInterfaceArmTest : public ::testing::Test {
 protected:
  void SetUp() override {
    memory_.Clear();
    process_memory_.Clear();
  }

  MemoryFake memory_;
  MemoryFake process_memory_;
};

TEST_F(ElfInterfaceArmTest, GetPrel32Addr) {
  ElfInterfaceArm interface(&memory_);
  memory_.SetData32(0x1000, 0x230000);

  uint32_t value;
  ASSERT_TRUE(interface.GetPrel31Addr(0x1000, &value));
  ASSERT_EQ(0x231000U, value);

  memory_.SetData32(0x1000, 0x80001000);
  ASSERT_TRUE(interface.GetPrel31Addr(0x1000, &value));
  ASSERT_EQ(0x2000U, value);

  memory_.SetData32(0x1000, 0x70001000);
  ASSERT_TRUE(interface.GetPrel31Addr(0x1000, &value));
  ASSERT_EQ(0xf0002000U, value);
}

TEST_F(ElfInterfaceArmTest, FindEntry_start_zero) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0);
  interface.set_total_entries(10);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfInterfaceArmTest, FindEntry_no_entries) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x100);
  interface.set_total_entries(0);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfInterfaceArmTest, FindEntry_no_valid_memory) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x100);
  interface.set_total_entries(2);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfInterfaceArmTest, FindEntry_ip_before_first) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(1);
  memory_.SetData32(0x1000, 0x6000);

  uint64_t entry_offset;
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
}

TEST_F(ElfInterfaceArmTest, FindEntry_single_entry_negative_value) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x8000);
  interface.set_total_entries(1);
  memory_.SetData32(0x8000, 0x7fffff00);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x7ff0, &entry_offset));
  ASSERT_EQ(0x8000U, entry_offset);
}

TEST_F(ElfInterfaceArmTest, FindEntry_two_entries) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(2);
  memory_.SetData32(0x1000, 0x6000);
  memory_.SetData32(0x1008, 0x7000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x7000, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);
}


TEST_F(ElfInterfaceArmTest, FindEntry_last_check_single_entry) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(1);
  memory_.SetData32(0x1000, 0x6000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x7000, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.SetData32(0x1000, 0x8000);
  ASSERT_TRUE(interface.FindEntry(0x7004, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);
}

TEST_F(ElfInterfaceArmTest, FindEntry_last_check_multiple_entries) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(2);
  memory_.SetData32(0x1000, 0x6000);
  memory_.SetData32(0x1008, 0x8000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x9008, &entry_offset));
  ASSERT_EQ(0x1008U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.SetData32(0x1000, 0x16000);
  memory_.SetData32(0x1008, 0x18000);
  ASSERT_TRUE(interface.FindEntry(0x9100, &entry_offset));
  ASSERT_EQ(0x1008U, entry_offset);
}

TEST_F(ElfInterfaceArmTest, FindEntry_multiple_entries_even) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(4);
  memory_.SetData32(0x1000, 0x6000);
  memory_.SetData32(0x1008, 0x7000);
  memory_.SetData32(0x1010, 0x8000);
  memory_.SetData32(0x1018, 0x9000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x9100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.SetData32(0x1000, 0x16000);
  memory_.SetData32(0x1008, 0x17000);
  memory_.SetData32(0x1010, 0x18000);
  memory_.SetData32(0x1018, 0x19000);
  ASSERT_TRUE(interface.FindEntry(0x9100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);
}

TEST_F(ElfInterfaceArmTest, FindEntry_multiple_entries_odd) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(5);
  memory_.SetData32(0x1000, 0x5000);
  memory_.SetData32(0x1008, 0x6000);
  memory_.SetData32(0x1010, 0x7000);
  memory_.SetData32(0x1018, 0x8000);
  memory_.SetData32(0x1020, 0x9000);

  uint64_t entry_offset;
  ASSERT_TRUE(interface.FindEntry(0x8100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);

  // To guarantee that we are using the cache on the second run,
  // set the memory to a different value.
  memory_.SetData32(0x1000, 0x15000);
  memory_.SetData32(0x1008, 0x16000);
  memory_.SetData32(0x1010, 0x17000);
  memory_.SetData32(0x1018, 0x18000);
  memory_.SetData32(0x1020, 0x19000);
  ASSERT_TRUE(interface.FindEntry(0x8100, &entry_offset));
  ASSERT_EQ(0x1010U, entry_offset);
}

TEST_F(ElfInterfaceArmTest, iterate) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(5);
  memory_.SetData32(0x1000, 0x5000);
  memory_.SetData32(0x1008, 0x6000);
  memory_.SetData32(0x1010, 0x7000);
  memory_.SetData32(0x1018, 0x8000);
  memory_.SetData32(0x1020, 0x9000);

  std::vector<uint32_t> entries;
  for (auto addr : interface) {
    entries.push_back(addr);
  }
  ASSERT_EQ(5U, entries.size());
  ASSERT_EQ(0x6000U, entries[0]);
  ASSERT_EQ(0x7008U, entries[1]);
  ASSERT_EQ(0x8010U, entries[2]);
  ASSERT_EQ(0x9018U, entries[3]);
  ASSERT_EQ(0xa020U, entries[4]);

  // Make sure the iterate cached the entries.
  memory_.SetData32(0x1000, 0x11000);
  memory_.SetData32(0x1008, 0x12000);
  memory_.SetData32(0x1010, 0x13000);
  memory_.SetData32(0x1018, 0x14000);
  memory_.SetData32(0x1020, 0x15000);

  entries.clear();
  for (auto addr : interface) {
    entries.push_back(addr);
  }
  ASSERT_EQ(5U, entries.size());
  ASSERT_EQ(0x6000U, entries[0]);
  ASSERT_EQ(0x7008U, entries[1]);
  ASSERT_EQ(0x8010U, entries[2]);
  ASSERT_EQ(0x9018U, entries[3]);
  ASSERT_EQ(0xa020U, entries[4]);
}

TEST_F(ElfInterfaceArmTest, FindEntry_load_bias) {
  ElfInterfaceArm interface(&memory_);
  interface.set_start_offset(0x1000);
  interface.set_total_entries(2);
  memory_.SetData32(0x1000, 0x6000);
  memory_.SetData32(0x1008, 0x8000);

  uint64_t entry_offset;
  interface.set_load_bias(0x2000);
  ASSERT_FALSE(interface.FindEntry(0x1000, &entry_offset));
  ASSERT_FALSE(interface.FindEntry(0x8000, &entry_offset));
  ASSERT_FALSE(interface.FindEntry(0x8fff, &entry_offset));
  ASSERT_TRUE(interface.FindEntry(0x9000, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);
  ASSERT_TRUE(interface.FindEntry(0xb007, &entry_offset));
  ASSERT_EQ(0x1000U, entry_offset);
  ASSERT_TRUE(interface.FindEntry(0xb008, &entry_offset));
  ASSERT_EQ(0x1008U, entry_offset);
}

TEST_F(ElfInterfaceArmTest, HandleType_not_arm_exidx) {
  ElfInterfaceArm interface(&memory_);

  ASSERT_FALSE(interface.HandleType(0x1000, PT_NULL));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_LOAD));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_DYNAMIC));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_INTERP));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_NOTE));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_SHLIB));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_PHDR));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_TLS));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_LOOS));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_HIOS));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_LOPROC));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_HIPROC));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_GNU_EH_FRAME));
  ASSERT_FALSE(interface.HandleType(0x1000, PT_GNU_STACK));
}

TEST_F(ElfInterfaceArmTest, HandleType_arm_exidx) {
  ElfInterfaceArm interface(&memory_);

  Elf32_Phdr phdr;
  interface.set_start_offset(0x1000);
  interface.set_total_entries(100);
  phdr.p_vaddr = 0x2000;
  phdr.p_memsz = 0xa00;

  // Verify that if reads fail, we don't set the values but still get true.
  ASSERT_TRUE(interface.HandleType(0x1000, 0x70000001));
  ASSERT_EQ(0x1000U, interface.start_offset());
  ASSERT_EQ(100U, interface.total_entries());

  // Verify that if the second read fails, we still don't set the values.
  memory_.SetData32(
      0x1000 + reinterpret_cast<uint64_t>(&phdr.p_vaddr) - reinterpret_cast<uint64_t>(&phdr),
      phdr.p_vaddr);
  ASSERT_TRUE(interface.HandleType(0x1000, 0x70000001));
  ASSERT_EQ(0x1000U, interface.start_offset());
  ASSERT_EQ(100U, interface.total_entries());

  // Everything is correct and present.
  memory_.SetData32(
      0x1000 + reinterpret_cast<uint64_t>(&phdr.p_memsz) - reinterpret_cast<uint64_t>(&phdr),
      phdr.p_memsz);
  ASSERT_TRUE(interface.HandleType(0x1000, 0x70000001));
  ASSERT_EQ(0x2000U, interface.start_offset());
  ASSERT_EQ(320U, interface.total_entries());

  // Non-zero load bias.
  interface.set_load_bias(0x1000);
  ASSERT_TRUE(interface.HandleType(0x1000, 0x70000001));
  ASSERT_EQ(0x1000U, interface.start_offset());
  ASSERT_EQ(320U, interface.total_entries());
}

TEST_F(ElfInterfaceArmTest, StepExidx) {
  ElfInterfaceArm interface(&memory_);

  // FindEntry fails.
  ASSERT_FALSE(interface.StepExidx(0x7000, nullptr, nullptr));

  // ExtractEntry should fail.
  interface.set_start_offset(0x1000);
  interface.set_total_entries(2);
  memory_.SetData32(0x1000, 0x6000);
  memory_.SetData32(0x1008, 0x8000);

  RegsArm regs;
  regs[ARM_REG_SP] = 0x1000;
  regs[ARM_REG_LR] = 0x20000;
  regs.set_sp(regs[ARM_REG_SP]);
  regs.set_pc(0x1234);
  ASSERT_FALSE(interface.StepExidx(0x7000, &regs, &process_memory_));

  // Eval should fail.
  memory_.SetData32(0x1004, 0x81000000);
  ASSERT_FALSE(interface.StepExidx(0x7000, &regs, &process_memory_));

  // Everything should pass.
  memory_.SetData32(0x1004, 0x80b0b0b0);
  ASSERT_TRUE(interface.StepExidx(0x7000, &regs, &process_memory_));
  ASSERT_EQ(0x1000U, regs.sp());
  ASSERT_EQ(0x1000U, regs[ARM_REG_SP]);
  ASSERT_EQ(0x20000U, regs.pc());
  ASSERT_EQ(0x20000U, regs[ARM_REG_PC]);
}

TEST_F(ElfInterfaceArmTest, StepExidx_pc_set) {
  ElfInterfaceArm interface(&memory_);

  interface.set_start_offset(0x1000);
  interface.set_total_entries(2);
  memory_.SetData32(0x1000, 0x6000);
  memory_.SetData32(0x1004, 0x808800b0);
  memory_.SetData32(0x1008, 0x8000);
  process_memory_.SetData32(0x10000, 0x10);

  RegsArm regs;
  regs[ARM_REG_SP] = 0x10000;
  regs[ARM_REG_LR] = 0x20000;
  regs.set_sp(regs[ARM_REG_SP]);
  regs.set_pc(0x1234);

  // Everything should pass.
  ASSERT_TRUE(interface.StepExidx(0x7000, &regs, &process_memory_));
  ASSERT_EQ(0x10004U, regs.sp());
  ASSERT_EQ(0x10004U, regs[ARM_REG_SP]);
  ASSERT_EQ(0x10U, regs.pc());
  ASSERT_EQ(0x10U, regs[ARM_REG_PC]);
}
