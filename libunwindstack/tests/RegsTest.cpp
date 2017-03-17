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

#include "Elf.h"
#include "ElfInterface.h"
#include "MapInfo.h"
#include "Regs.h"

#include "MemoryFake.h"

class ElfFake : public Elf {
 public:
  ElfFake(Memory* memory) : Elf(memory) { valid_ = true; }
  virtual ~ElfFake() = default;

  void set_elf_interface(ElfInterface* interface) { interface_.reset(interface); }
};

class ElfInterfaceFake : public ElfInterface {
 public:
  ElfInterfaceFake(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterfaceFake() = default;

  void set_load_bias(uint64_t load_bias) { load_bias_ = load_bias; }

  bool Init() override { return false; }
  void InitHeaders() override {}
  bool GetSoname(std::string*) override { return false; }
  bool GetFunctionName(uint64_t, std::string*, uint64_t*) override { return false; }
  bool Step(uint64_t, Regs*, Memory*) override { return false; }
};

template <typename TypeParam>
class RegsTestTmpl : public RegsTmpl<TypeParam> {
 public:
  RegsTestTmpl(uint16_t total_regs, uint16_t regs_sp)
      : RegsTmpl<TypeParam>(total_regs, regs_sp, Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
  RegsTestTmpl(uint16_t total_regs, uint16_t regs_sp, Regs::Location return_loc)
      : RegsTmpl<TypeParam>(total_regs, regs_sp, return_loc) {}
  virtual ~RegsTestTmpl() = default;

  uint64_t GetAdjustedPc(uint64_t, Elf*) { return 0; }
};

class RegsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    memory_ = new MemoryFake;
    elf_.reset(new ElfFake(memory_));
    elf_interface_ = new ElfInterfaceFake(elf_->memory());
    elf_->set_elf_interface(elf_interface_);
  }

  template <typename AddressType>
  void regs_rel_pc();

  template <typename AddressType>
  void regs_return_address_register();

  ElfInterfaceFake* elf_interface_;
  MemoryFake* memory_;
  std::unique_ptr<ElfFake> elf_;
};

TEST_F(RegsTest, regs32) {
  RegsTestTmpl<uint32_t> regs32(50, 10);
  ASSERT_EQ(50U, regs32.total_regs());
  ASSERT_EQ(10U, regs32.sp_reg());

  uint32_t* raw = reinterpret_cast<uint32_t*>(regs32.RawData());
  for (size_t i = 0; i < 50; i++) {
    raw[i] = 0xf0000000 + i;
  }
  regs32.set_pc(0xf0120340);
  regs32.set_sp(0xa0ab0cd0);

  for (size_t i = 0; i < 50; i++) {
    ASSERT_EQ(0xf0000000U + i, regs32[i]) << "Failed comparing register " << i;
  }

  ASSERT_EQ(0xf0120340U, regs32.pc());
  ASSERT_EQ(0xa0ab0cd0U, regs32.sp());

  regs32[32] = 10;
  ASSERT_EQ(10U, regs32[32]);
}

TEST_F(RegsTest, regs64) {
  RegsTestTmpl<uint64_t> regs64(30, 12);
  ASSERT_EQ(30U, regs64.total_regs());
  ASSERT_EQ(12U, regs64.sp_reg());

  uint64_t* raw = reinterpret_cast<uint64_t*>(regs64.RawData());
  for (size_t i = 0; i < 30; i++) {
    raw[i] = 0xf123456780000000UL + i;
  }
  regs64.set_pc(0xf123456780102030UL);
  regs64.set_sp(0xa123456780a0b0c0UL);

  for (size_t i = 0; i < 30; i++) {
    ASSERT_EQ(0xf123456780000000U + i, regs64[i]) << "Failed reading register " << i;
  }

  ASSERT_EQ(0xf123456780102030UL, regs64.pc());
  ASSERT_EQ(0xa123456780a0b0c0UL, regs64.sp());

  regs64[8] = 10;
  ASSERT_EQ(10U, regs64[8]);
}

template <typename AddressType>
void RegsTest::regs_rel_pc() {
  RegsTestTmpl<AddressType> regs(30, 12);

  elf_interface_->set_load_bias(0);
  MapInfo map_info{.start = 0x1000, .end = 0x2000};
  regs.set_pc(0x1101);
  ASSERT_EQ(0x101U, regs.GetRelPc(elf_.get(), &map_info));
  elf_interface_->set_load_bias(0x3000);
  ASSERT_EQ(0x3101U, regs.GetRelPc(elf_.get(), &map_info));
}

TEST_F(RegsTest, regs32_rel_pc) {
  regs_rel_pc<uint32_t>();
}

TEST_F(RegsTest, regs64_rel_pc) {
  regs_rel_pc<uint64_t>();
}

template <typename AddressType>
void RegsTest::regs_return_address_register() {
  RegsTestTmpl<AddressType> regs(20, 10, Regs::Location(Regs::LOCATION_REGISTER, 5));

  regs[5] = 0x12345;
  uint64_t value;
  ASSERT_TRUE(regs.GetReturnAddressFromDefault(memory_, &value));
  ASSERT_EQ(0x12345U, value);
}

TEST_F(RegsTest, regs32_return_address_register) {
  regs_return_address_register<uint32_t>();
}

TEST_F(RegsTest, regs64_return_address_register) {
  regs_return_address_register<uint64_t>();
}

TEST_F(RegsTest, regs32_return_address_sp_offset) {
  RegsTestTmpl<uint32_t> regs(20, 10, Regs::Location(Regs::LOCATION_SP_OFFSET, -2));

  regs.set_sp(0x2002);
  memory_->SetData32(0x2000, 0x12345678);
  uint64_t value;
  ASSERT_TRUE(regs.GetReturnAddressFromDefault(memory_, &value));
  ASSERT_EQ(0x12345678U, value);
}

TEST_F(RegsTest, regs64_return_address_sp_offset) {
  RegsTestTmpl<uint64_t> regs(20, 10, Regs::Location(Regs::LOCATION_SP_OFFSET, -8));

  regs.set_sp(0x2008);
  memory_->SetData64(0x2000, 0x12345678aabbccddULL);
  uint64_t value;
  ASSERT_TRUE(regs.GetReturnAddressFromDefault(memory_, &value));
  ASSERT_EQ(0x12345678aabbccddULL, value);
}

TEST_F(RegsTest, rel_pc) {
  RegsArm64 arm64;
  ASSERT_EQ(0xcU, arm64.GetAdjustedPc(0x10, elf_.get()));
  ASSERT_EQ(0x0U, arm64.GetAdjustedPc(0x4, elf_.get()));
  ASSERT_EQ(0x3U, arm64.GetAdjustedPc(0x3, elf_.get()));
  ASSERT_EQ(0x2U, arm64.GetAdjustedPc(0x2, elf_.get()));
  ASSERT_EQ(0x1U, arm64.GetAdjustedPc(0x1, elf_.get()));
  ASSERT_EQ(0x0U, arm64.GetAdjustedPc(0x0, elf_.get()));

  RegsX86 x86;
  ASSERT_EQ(0xffU,  x86.GetAdjustedPc(0x100, elf_.get()));
  ASSERT_EQ(0x1U,  x86.GetAdjustedPc(0x2, elf_.get()));
  ASSERT_EQ(0x0U,  x86.GetAdjustedPc(0x1, elf_.get()));
  ASSERT_EQ(0x0U,  x86.GetAdjustedPc(0x0, elf_.get()));

  RegsX86_64 x86_64;
  ASSERT_EQ(0xffU,  x86_64.GetAdjustedPc(0x100, elf_.get()));
  ASSERT_EQ(0x1U,  x86_64.GetAdjustedPc(0x2, elf_.get()));
  ASSERT_EQ(0x0U,  x86_64.GetAdjustedPc(0x1, elf_.get()));
  ASSERT_EQ(0x0U,  x86_64.GetAdjustedPc(0x0, elf_.get()));
}

TEST_F(RegsTest, rel_pc_arm) {
  RegsArm arm;

  // Check fence posts.
  elf_interface_->set_load_bias(0);
  ASSERT_EQ(3U,  arm.GetAdjustedPc(0x5, elf_.get()));
  ASSERT_EQ(4U,  arm.GetAdjustedPc(0x4, elf_.get()));
  ASSERT_EQ(3U,  arm.GetAdjustedPc(0x3, elf_.get()));
  ASSERT_EQ(2U,  arm.GetAdjustedPc(0x2, elf_.get()));
  ASSERT_EQ(1U,  arm.GetAdjustedPc(0x1, elf_.get()));
  ASSERT_EQ(0U,  arm.GetAdjustedPc(0x0, elf_.get()));

  elf_interface_->set_load_bias(0x100);
  ASSERT_EQ(0xffU,  arm.GetAdjustedPc(0xff, elf_.get()));
  ASSERT_EQ(0x103U,  arm.GetAdjustedPc(0x105, elf_.get()));
  ASSERT_EQ(0x104U,  arm.GetAdjustedPc(0x104, elf_.get()));
  ASSERT_EQ(0x103U,  arm.GetAdjustedPc(0x103, elf_.get()));
  ASSERT_EQ(0x102U,  arm.GetAdjustedPc(0x102, elf_.get()));
  ASSERT_EQ(0x101U,  arm.GetAdjustedPc(0x101, elf_.get()));
  ASSERT_EQ(0x100U,  arm.GetAdjustedPc(0x100, elf_.get()));

  // Check thumb instructions handling.
  elf_interface_->set_load_bias(0);
  memory_->SetData32(0x2000, 0);
  ASSERT_EQ(0x2003U,  arm.GetAdjustedPc(0x2005, elf_.get()));
  memory_->SetData32(0x2000, 0xe000f000);
  ASSERT_EQ(0x2001U,  arm.GetAdjustedPc(0x2005, elf_.get()));

  elf_interface_->set_load_bias(0x400);
  memory_->SetData32(0x2100, 0);
  ASSERT_EQ(0x2503U,  arm.GetAdjustedPc(0x2505, elf_.get()));
  memory_->SetData32(0x2100, 0xf111f111);
  ASSERT_EQ(0x2501U,  arm.GetAdjustedPc(0x2505, elf_.get()));
}

TEST_F(RegsTest, elf_invalid) {
  Elf invalid_elf(new MemoryFake);
  RegsArm regs_arm;
  RegsArm64 regs_arm64;
  RegsX86 regs_x86;
  RegsX86_64 regs_x86_64;
  MapInfo map_info{.start = 0x1000, .end = 0x2000};

  regs_arm.set_pc(0x1500);
  ASSERT_EQ(0x500U, regs_arm.GetRelPc(&invalid_elf, &map_info));
  ASSERT_EQ(0x500U, regs_arm.GetAdjustedPc(0x500U, &invalid_elf));

  regs_arm64.set_pc(0x1600);
  ASSERT_EQ(0x600U, regs_arm64.GetRelPc(&invalid_elf, &map_info));
  ASSERT_EQ(0x600U, regs_arm64.GetAdjustedPc(0x600U, &invalid_elf));

  regs_x86.set_pc(0x1700);
  ASSERT_EQ(0x700U, regs_x86.GetRelPc(&invalid_elf, &map_info));
  ASSERT_EQ(0x700U, regs_x86.GetAdjustedPc(0x700U, &invalid_elf));

  regs_x86_64.set_pc(0x1800);
  ASSERT_EQ(0x800U, regs_x86_64.GetRelPc(&invalid_elf, &map_info));
  ASSERT_EQ(0x800U, regs_x86_64.GetAdjustedPc(0x800U, &invalid_elf));
}
