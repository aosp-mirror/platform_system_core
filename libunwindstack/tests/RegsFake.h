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

#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

namespace unwindstack {

template <typename TypeParam>
class RegsFake : public RegsImpl<TypeParam> {
 public:
  RegsFake(uint16_t total_regs, uint16_t sp_reg)
      : RegsImpl<TypeParam>(total_regs, sp_reg, Regs::Location(Regs::LOCATION_UNKNOWN, 0)) {}
  virtual ~RegsFake() = default;

  uint32_t MachineType() override { return 0; }

  uint64_t GetAdjustedPc(uint64_t, Elf*) override { return 0; }
  void SetFromRaw() override {}
  bool SetPcFromReturnAddress(Memory*) override { return false; }
  bool StepIfSignalHandler(uint64_t, Elf*, Memory*) override { return false; }
  bool GetReturnAddressFromDefault(Memory*, uint64_t*) { return false; }
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_TESTS_REGS_FAKE_H
