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

#ifndef _LIBUNWINDSTACK_TESTS_REGS_FAKE_H
#define _LIBUNWINDSTACK_TESTS_REGS_FAKE_H

#include <stdint.h>

#include <unwindstack/Elf.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

namespace unwindstack {

class RegsFake : public Regs {
 public:
  RegsFake(uint16_t total_regs, uint16_t sp_reg)
      : Regs(total_regs, sp_reg, Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
  virtual ~RegsFake() = default;

  ArchEnum Arch() override { return fake_arch_; }
  void* RawData() override { return nullptr; }
  uint64_t pc() override { return fake_pc_; }
  uint64_t sp() override { return fake_sp_; }
  bool SetPcFromReturnAddress(Memory*) override {
    if (!fake_return_address_valid_) {
      return false;
    }
    fake_pc_ = fake_return_address_;
    return true;
  }

  void IterateRegisters(std::function<void(const char*, uint64_t)>) override {}

  bool Is32Bit() { return false; }

  uint64_t GetAdjustedPc(uint64_t rel_pc, Elf*) override { return rel_pc - 2; }

  bool StepIfSignalHandler(uint64_t, Elf*, Memory*) override { return false; }

  void SetFromRaw() override {}

  void FakeSetArch(ArchEnum arch) { fake_arch_ = arch; }
  void FakeSetPc(uint64_t pc) { fake_pc_ = pc; }
  void FakeSetSp(uint64_t sp) { fake_sp_ = sp; }
  void FakeSetReturnAddress(uint64_t return_address) { fake_return_address_ = return_address; }
  void FakeSetReturnAddressValid(bool valid) { fake_return_address_valid_ = valid; }

 private:
  ArchEnum fake_arch_ = ARCH_UNKNOWN;
  uint64_t fake_pc_ = 0;
  uint64_t fake_sp_ = 0;
  bool fake_return_address_valid_ = false;
  uint64_t fake_return_address_ = 0;
};

template <typename TypeParam>
class RegsImplFake : public RegsImpl<TypeParam> {
 public:
  RegsImplFake(uint16_t total_regs, uint16_t sp_reg)
      : RegsImpl<TypeParam>(total_regs, sp_reg, Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
  virtual ~RegsImplFake() = default;

  ArchEnum Arch() override { return ARCH_UNKNOWN; }

  uint64_t GetAdjustedPc(uint64_t, Elf*) override { return 0; }
  void SetFromRaw() override {}
  bool SetPcFromReturnAddress(Memory*) override { return false; }
  bool StepIfSignalHandler(uint64_t, Elf*, Memory*) override { return false; }

  void FakeSetPc(uint64_t pc) { this->pc_ = pc; }
  void FakeSetSp(uint64_t sp) { this->sp_ = sp; }
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_TESTS_REGS_FAKE_H
