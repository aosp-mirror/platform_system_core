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
#include <string.h>

#include <memory>
#include <string>

#define LOG_TAG "unwind"
#include <log/log.h>

#include <unwindstack/Elf.h>
#include <unwindstack/ElfInterface.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

#include "ElfInterfaceArm.h"
#include "Machine.h"
#include "Symbols.h"

namespace unwindstack {

bool Elf::Init(bool init_gnu_debugdata) {
  load_bias_ = 0;
  if (!memory_) {
    return false;
  }

  interface_.reset(CreateInterfaceFromMemory(memory_.get()));
  if (!interface_) {
    return false;
  }

  valid_ = interface_->Init(&load_bias_);
  if (valid_) {
    interface_->InitHeaders();
    if (init_gnu_debugdata) {
      InitGnuDebugdata();
    } else {
      gnu_debugdata_interface_.reset(nullptr);
    }
  } else {
    interface_.reset(nullptr);
  }
  return valid_;
}

// It is expensive to initialize the .gnu_debugdata section. Provide a method
// to initialize this data separately.
void Elf::InitGnuDebugdata() {
  if (!valid_ || interface_->gnu_debugdata_offset() == 0) {
    return;
  }

  gnu_debugdata_memory_.reset(interface_->CreateGnuDebugdataMemory());
  gnu_debugdata_interface_.reset(CreateInterfaceFromMemory(gnu_debugdata_memory_.get()));
  ElfInterface* gnu = gnu_debugdata_interface_.get();
  if (gnu == nullptr) {
    return;
  }

  // Ignore the load_bias from the compressed section, the correct load bias
  // is in the uncompressed data.
  uint64_t load_bias;
  if (gnu->Init(&load_bias)) {
    gnu->InitHeaders();
  } else {
    // Free all of the memory associated with the gnu_debugdata section.
    gnu_debugdata_memory_.reset(nullptr);
    gnu_debugdata_interface_.reset(nullptr);
  }
}

bool Elf::GetSoname(std::string* name) {
  return valid_ && interface_->GetSoname(name);
}

uint64_t Elf::GetRelPc(uint64_t pc, const MapInfo* map_info) {
  return pc - map_info->start + load_bias_ + map_info->elf_offset;
}

bool Elf::GetFunctionName(uint64_t addr, std::string* name, uint64_t* func_offset) {
  return valid_ && (interface_->GetFunctionName(addr, load_bias_, name, func_offset) ||
                    (gnu_debugdata_interface_ && gnu_debugdata_interface_->GetFunctionName(
                                                     addr, load_bias_, name, func_offset)));
}

// The relative pc is always relative to the start of the map from which it comes.
bool Elf::Step(uint64_t rel_pc, uint64_t elf_offset, Regs* regs, Memory* process_memory,
               bool* finished) {
  if (!valid_) {
    return false;
  }

  // The relative pc expectd by StepIfSignalHandler is relative to the start of the elf.
  if (regs->StepIfSignalHandler(rel_pc + elf_offset, this, process_memory)) {
    *finished = false;
    return true;
  }

  // Adjust the load bias to get the real relative pc.
  if (rel_pc < load_bias_) {
    return false;
  }
  rel_pc -= load_bias_;

  return interface_->Step(rel_pc, regs, process_memory, finished) ||
         (gnu_debugdata_interface_ &&
          gnu_debugdata_interface_->Step(rel_pc, regs, process_memory, finished));
}

bool Elf::IsValidElf(Memory* memory) {
  if (memory == nullptr) {
    return false;
  }

  // Verify that this is a valid elf file.
  uint8_t e_ident[SELFMAG + 1];
  if (!memory->ReadFully(0, e_ident, SELFMAG)) {
    return false;
  }

  if (memcmp(e_ident, ELFMAG, SELFMAG) != 0) {
    return false;
  }
  return true;
}

void Elf::GetInfo(Memory* memory, bool* valid, uint64_t* size) {
  if (!IsValidElf(memory)) {
    *valid = false;
    return;
  }
  *size = 0;
  *valid = true;

  // Now read the section header information.
  uint8_t class_type;
  if (!memory->ReadFully(EI_CLASS, &class_type, 1)) {
    return;
  }
  if (class_type == ELFCLASS32) {
    ElfInterface32::GetMaxSize(memory, size);
  } else if (class_type == ELFCLASS64) {
    ElfInterface64::GetMaxSize(memory, size);
  } else {
    *valid = false;
  }
}

ElfInterface* Elf::CreateInterfaceFromMemory(Memory* memory) {
  if (!IsValidElf(memory)) {
    return nullptr;
  }

  std::unique_ptr<ElfInterface> interface;
  if (!memory->ReadFully(EI_CLASS, &class_type_, 1)) {
    return nullptr;
  }
  if (class_type_ == ELFCLASS32) {
    Elf32_Half e_machine;
    if (!memory->ReadFully(EI_NIDENT + sizeof(Elf32_Half), &e_machine, sizeof(e_machine))) {
      return nullptr;
    }

    if (e_machine != EM_ARM && e_machine != EM_386) {
      // Unsupported.
      ALOGI("32 bit elf that is neither arm nor x86: e_machine = %d\n", e_machine);
      return nullptr;
    }

    machine_type_ = e_machine;
    if (e_machine == EM_ARM) {
      interface.reset(new ElfInterfaceArm(memory));
    } else if (e_machine == EM_386) {
      interface.reset(new ElfInterface32(memory));
    } else {
      ALOGI("32 bit elf that is neither arm nor x86: e_machine = %d\n", e_machine);
      return nullptr;
    }
  } else if (class_type_ == ELFCLASS64) {
    Elf64_Half e_machine;
    if (!memory->ReadFully(EI_NIDENT + sizeof(Elf64_Half), &e_machine, sizeof(e_machine))) {
      return nullptr;
    }
    if (e_machine != EM_AARCH64 && e_machine != EM_X86_64) {
      // Unsupported.
      ALOGI("64 bit elf that is neither aarch64 nor x86_64: e_machine = %d\n", e_machine);
      return nullptr;
    }
    machine_type_ = e_machine;
    interface.reset(new ElfInterface64(memory));
  }

  return interface.release();
}

}  // namespace unwindstack
