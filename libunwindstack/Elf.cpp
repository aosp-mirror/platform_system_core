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

bool Elf::Init() {
  if (!memory_) {
    return false;
  }

  interface_.reset(CreateInterfaceFromMemory(memory_.get()));
  if (!interface_) {
    return false;
  }

  valid_ = interface_->Init();
  if (valid_) {
    interface_->InitHeaders();
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
  if (gnu->Init()) {
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
  uint64_t load_bias = 0;
  if (valid()) {
    load_bias = interface_->load_bias();
  }

  return pc - map_info->start + load_bias + map_info->elf_offset;
}

bool Elf::GetFunctionName(uint64_t addr, std::string* name, uint64_t* func_offset) {
  return valid_ && (interface_->GetFunctionName(addr, name, func_offset) ||
                    (gnu_debugdata_interface_ &&
                     gnu_debugdata_interface_->GetFunctionName(addr, name, func_offset)));
}

bool Elf::Step(uint64_t rel_pc, Regs* regs, Memory* process_memory, bool* finished) {
  if (!valid_) {
    return false;
  }
  if (regs->StepIfSignalHandler(rel_pc, this, process_memory)) {
    *finished = false;
    return true;
  }
  return interface_->Step(rel_pc, regs, process_memory, finished) ||
         (gnu_debugdata_interface_ &&
          gnu_debugdata_interface_->Step(rel_pc, regs, process_memory, finished));
}

uint64_t Elf::GetLoadBias() {
  if (!valid_) return 0;
  return interface_->load_bias();
}

bool Elf::IsValidElf(Memory* memory) {
  if (memory == nullptr) {
    return false;
  }

  // Verify that this is a valid elf file.
  uint8_t e_ident[SELFMAG + 1];
  if (!memory->Read(0, e_ident, SELFMAG)) {
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
  if (!memory->Read(EI_CLASS, &class_type, 1)) {
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
  if (!memory->Read(EI_CLASS, &class_type_, 1)) {
    return nullptr;
  }
  if (class_type_ == ELFCLASS32) {
    Elf32_Half e_machine;
    if (!memory->Read(EI_NIDENT + sizeof(Elf32_Half), &e_machine, sizeof(e_machine))) {
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
    if (!memory->Read(EI_NIDENT + sizeof(Elf64_Half), &e_machine, sizeof(e_machine))) {
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
