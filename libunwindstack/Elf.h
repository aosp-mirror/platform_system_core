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

#ifndef _LIBUNWINDSTACK_ELF_H
#define _LIBUNWINDSTACK_ELF_H

#include <stddef.h>

#include <memory>
#include <string>

#include "ElfInterface.h"
#include "Memory.h"

#if !defined(EM_AARCH64)
#define EM_AARCH64 183
#endif

// Forward declaration.
class Regs;

class Elf {
 public:
  Elf(Memory* memory) : memory_(memory) {}
  virtual ~Elf() = default;

  bool Init();

  void InitGnuDebugdata();

  bool GetSoname(std::string* name) {
    return valid_ && interface_->GetSoname(name);
  }

  bool GetFunctionName(uint64_t addr, std::string* name, uint64_t* func_offset) {
    return valid_ && (interface_->GetFunctionName(addr, name, func_offset) ||
                      (gnu_debugdata_interface_ &&
                       gnu_debugdata_interface_->GetFunctionName(addr, name, func_offset)));
  }

  bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory) {
    return valid_ && (interface_->Step(rel_pc, regs, process_memory) ||
                      (gnu_debugdata_interface_ &&
                       gnu_debugdata_interface_->Step(rel_pc, regs, process_memory)));
  }

  ElfInterface* CreateInterfaceFromMemory(Memory* memory);

  bool valid() { return valid_; }

  uint32_t machine_type() { return machine_type_; }

  uint8_t class_type() { return class_type_; }

  Memory* memory() { return memory_.get(); }

  ElfInterface* interface() { return interface_.get(); }

  ElfInterface* gnu_debugdata_interface() { return gnu_debugdata_interface_.get(); }

  static bool IsValidElf(Memory* memory);

 protected:
  bool valid_ = false;
  std::unique_ptr<ElfInterface> interface_;
  std::unique_ptr<Memory> memory_;
  uint32_t machine_type_;
  uint8_t class_type_;

  std::unique_ptr<Memory> gnu_debugdata_memory_;
  std::unique_ptr<ElfInterface> gnu_debugdata_interface_;
};

#endif  // _LIBUNWINDSTACK_ELF_H
