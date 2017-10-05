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

#ifndef _LIBUNWINDSTACK_TESTS_ELF_FAKE_H
#define _LIBUNWINDSTACK_TESTS_ELF_FAKE_H

#include <stdint.h>

#include <deque>
#include <string>

#include <unwindstack/Elf.h>
#include <unwindstack/ElfInterface.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

namespace unwindstack {

struct StepData {
  StepData(uint64_t pc, uint64_t sp, bool finished) : pc(pc), sp(sp), finished(finished) {}
  uint64_t pc;
  uint64_t sp;
  bool finished;
};

struct FunctionData {
  FunctionData(std::string name, uint64_t offset) : name(name), offset(offset) {}

  std::string name;
  uint64_t offset;
};

class ElfFake : public Elf {
 public:
  ElfFake(Memory* memory) : Elf(memory) { valid_ = true; }
  virtual ~ElfFake() = default;

  void FakeSetInterface(ElfInterface* interface) { interface_.reset(interface); }
};

class ElfInterfaceFake : public ElfInterface {
 public:
  ElfInterfaceFake(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterfaceFake() = default;

  bool Init() override { return false; }
  void InitHeaders() override {}
  bool GetSoname(std::string*) override { return false; }

  bool GetFunctionName(uint64_t, std::string*, uint64_t*) override;

  bool Step(uint64_t, Regs*, Memory*, bool*) override;

  void FakeSetLoadBias(uint64_t load_bias) { load_bias_ = load_bias; }

  static void FakePushFunctionData(const FunctionData data) { functions_.push_back(data); }
  static void FakePushStepData(const StepData data) { steps_.push_back(data); }

  static void FakeClear() {
    functions_.clear();
    steps_.clear();
  }

 private:
  static std::deque<FunctionData> functions_;
  static std::deque<StepData> steps_;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_TESTS_ELF_FAKE_H
