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

#include <elf.h>
#include <stdint.h>

#include <memory>
#include <string>

#include <7zCrc.h>
#include <Xz.h>
#include <XzCrc64.h>

#include <unwindstack/DwarfSection.h>
#include <unwindstack/ElfInterface.h>
#include <unwindstack/Log.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

#include "DwarfDebugFrame.h"
#include "DwarfEhFrame.h"
#include "Symbols.h"

namespace unwindstack {

ElfInterface::~ElfInterface() {
  for (auto symbol : symbols_) {
    delete symbol;
  }
}

Memory* ElfInterface::CreateGnuDebugdataMemory() {
  if (gnu_debugdata_offset_ == 0 || gnu_debugdata_size_ == 0) {
    return nullptr;
  }

  // TODO: Only call these initialization functions once.
  CrcGenerateTable();
  Crc64GenerateTable();

  std::vector<uint8_t> src(gnu_debugdata_size_);
  if (!memory_->Read(gnu_debugdata_offset_, src.data(), gnu_debugdata_size_)) {
    gnu_debugdata_offset_ = 0;
    gnu_debugdata_size_ = static_cast<uint64_t>(-1);
    return nullptr;
  }

  ISzAlloc alloc;
  CXzUnpacker state;
  alloc.Alloc = [](void*, size_t size) { return malloc(size); };
  alloc.Free = [](void*, void* ptr) { return free(ptr); };

  XzUnpacker_Construct(&state, &alloc);

  std::unique_ptr<MemoryBuffer> dst(new MemoryBuffer);
  int return_val;
  size_t src_offset = 0;
  size_t dst_offset = 0;
  ECoderStatus status;
  dst->Resize(5 * gnu_debugdata_size_);
  do {
    size_t src_remaining = src.size() - src_offset;
    size_t dst_remaining = dst->Size() - dst_offset;
    if (dst_remaining < 2 * gnu_debugdata_size_) {
      dst->Resize(dst->Size() + 2 * gnu_debugdata_size_);
      dst_remaining += 2 * gnu_debugdata_size_;
    }
    return_val = XzUnpacker_Code(&state, dst->GetPtr(dst_offset), &dst_remaining, &src[src_offset],
                                 &src_remaining, CODER_FINISH_ANY, &status);
    src_offset += src_remaining;
    dst_offset += dst_remaining;
  } while (return_val == SZ_OK && status == CODER_STATUS_NOT_FINISHED);
  XzUnpacker_Free(&state);
  if (return_val != SZ_OK || !XzUnpacker_IsStreamWasFinished(&state)) {
    gnu_debugdata_offset_ = 0;
    gnu_debugdata_size_ = static_cast<uint64_t>(-1);
    return nullptr;
  }

  // Shrink back down to the exact size.
  dst->Resize(dst_offset);

  return dst.release();
}

template <typename AddressType>
void ElfInterface::InitHeadersWithTemplate() {
  if (eh_frame_offset_ != 0) {
    eh_frame_.reset(new DwarfEhFrame<AddressType>(memory_));
    if (!eh_frame_->Init(eh_frame_offset_, eh_frame_size_)) {
      eh_frame_.reset(nullptr);
      eh_frame_offset_ = 0;
      eh_frame_size_ = static_cast<uint64_t>(-1);
    }
  }

  if (debug_frame_offset_ != 0) {
    debug_frame_.reset(new DwarfDebugFrame<AddressType>(memory_));
    if (!debug_frame_->Init(debug_frame_offset_, debug_frame_size_)) {
      debug_frame_.reset(nullptr);
      debug_frame_offset_ = 0;
      debug_frame_size_ = static_cast<uint64_t>(-1);
    }
  }
}

template <typename EhdrType, typename PhdrType, typename ShdrType>
bool ElfInterface::ReadAllHeaders() {
  EhdrType ehdr;
  if (!memory_->Read(0, &ehdr, sizeof(ehdr))) {
    return false;
  }

  if (!ReadProgramHeaders<EhdrType, PhdrType>(ehdr)) {
    return false;
  }

  // We could still potentially unwind without the section header
  // information, so ignore any errors.
  if (!ReadSectionHeaders<EhdrType, ShdrType>(ehdr)) {
    log(0, "Malformed section header found, ignoring...");
  }
  return true;
}

template <typename EhdrType, typename PhdrType>
bool ElfInterface::ReadProgramHeaders(const EhdrType& ehdr) {
  uint64_t offset = ehdr.e_phoff;
  for (size_t i = 0; i < ehdr.e_phnum; i++, offset += ehdr.e_phentsize) {
    PhdrType phdr;
    if (!memory_->ReadField(offset, &phdr, &phdr.p_type, sizeof(phdr.p_type))) {
      return false;
    }

    if (HandleType(offset, phdr.p_type)) {
      continue;
    }

    switch (phdr.p_type) {
    case PT_LOAD:
    {
      // Get the flags first, if this isn't an executable header, ignore it.
      if (!memory_->ReadField(offset, &phdr, &phdr.p_flags, sizeof(phdr.p_flags))) {
        return false;
      }
      if ((phdr.p_flags & PF_X) == 0) {
        continue;
      }

      if (!memory_->ReadField(offset, &phdr, &phdr.p_vaddr, sizeof(phdr.p_vaddr))) {
        return false;
      }
      if (!memory_->ReadField(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
        return false;
      }
      if (!memory_->ReadField(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
        return false;
      }
      pt_loads_[phdr.p_offset] = LoadInfo{phdr.p_offset, phdr.p_vaddr,
                                          static_cast<size_t>(phdr.p_memsz)};
      if (phdr.p_offset == 0) {
        load_bias_ = phdr.p_vaddr;
      }
      break;
    }

    case PT_GNU_EH_FRAME:
      if (!memory_->ReadField(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
        return false;
      }
      eh_frame_offset_ = phdr.p_offset;
      if (!memory_->ReadField(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
        return false;
      }
      eh_frame_size_ = phdr.p_memsz;
      break;

    case PT_DYNAMIC:
      if (!memory_->ReadField(offset, &phdr, &phdr.p_offset, sizeof(phdr.p_offset))) {
        return false;
      }
      dynamic_offset_ = phdr.p_offset;
      if (!memory_->ReadField(offset, &phdr, &phdr.p_memsz, sizeof(phdr.p_memsz))) {
        return false;
      }
      dynamic_size_ = phdr.p_memsz;
      break;
    }
  }
  return true;
}

template <typename EhdrType, typename ShdrType>
bool ElfInterface::ReadSectionHeaders(const EhdrType& ehdr) {
  uint64_t offset = ehdr.e_shoff;
  uint64_t sec_offset = 0;
  uint64_t sec_size = 0;

  // Get the location of the section header names.
  // If something is malformed in the header table data, we aren't going
  // to terminate, we'll simply ignore this part.
  ShdrType shdr;
  if (ehdr.e_shstrndx < ehdr.e_shnum) {
    uint64_t sh_offset = offset + ehdr.e_shstrndx * ehdr.e_shentsize;
    if (memory_->ReadField(sh_offset, &shdr, &shdr.sh_offset, sizeof(shdr.sh_offset)) &&
        memory_->ReadField(sh_offset, &shdr, &shdr.sh_size, sizeof(shdr.sh_size))) {
      sec_offset = shdr.sh_offset;
      sec_size = shdr.sh_size;
    }
  }

  // Skip the first header, it's always going to be NULL.
  offset += ehdr.e_shentsize;
  for (size_t i = 1; i < ehdr.e_shnum; i++, offset += ehdr.e_shentsize) {
    if (!memory_->ReadField(offset, &shdr, &shdr.sh_type, sizeof(shdr.sh_type))) {
      return false;
    }

    if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
      if (!memory_->Read(offset, &shdr, sizeof(shdr))) {
        return false;
      }
      // Need to go get the information about the section that contains
      // the string terminated names.
      ShdrType str_shdr;
      if (shdr.sh_link >= ehdr.e_shnum) {
        return false;
      }
      uint64_t str_offset = ehdr.e_shoff + shdr.sh_link * ehdr.e_shentsize;
      if (!memory_->ReadField(str_offset, &str_shdr, &str_shdr.sh_type, sizeof(str_shdr.sh_type))) {
        return false;
      }
      if (str_shdr.sh_type != SHT_STRTAB) {
        return false;
      }
      if (!memory_->ReadField(str_offset, &str_shdr, &str_shdr.sh_offset,
                              sizeof(str_shdr.sh_offset))) {
        return false;
      }
      if (!memory_->ReadField(str_offset, &str_shdr, &str_shdr.sh_size, sizeof(str_shdr.sh_size))) {
        return false;
      }
      symbols_.push_back(new Symbols(shdr.sh_offset, shdr.sh_size, shdr.sh_entsize,
                                     str_shdr.sh_offset, str_shdr.sh_size));
    } else if (shdr.sh_type == SHT_PROGBITS && sec_size != 0) {
      // Look for the .debug_frame and .gnu_debugdata.
      if (!memory_->ReadField(offset, &shdr, &shdr.sh_name, sizeof(shdr.sh_name))) {
        return false;
      }
      if (shdr.sh_name < sec_size) {
        std::string name;
        if (memory_->ReadString(sec_offset + shdr.sh_name, &name)) {
          uint64_t* offset_ptr = nullptr;
          uint64_t* size_ptr = nullptr;
          if (name == ".debug_frame") {
            offset_ptr = &debug_frame_offset_;
            size_ptr = &debug_frame_size_;
          } else if (name == ".gnu_debugdata") {
            offset_ptr = &gnu_debugdata_offset_;
            size_ptr = &gnu_debugdata_size_;
          }
          if (offset_ptr != nullptr &&
              memory_->ReadField(offset, &shdr, &shdr.sh_offset, sizeof(shdr.sh_offset)) &&
              memory_->ReadField(offset, &shdr, &shdr.sh_size, sizeof(shdr.sh_size))) {
            *offset_ptr = shdr.sh_offset;
            *size_ptr = shdr.sh_size;
          }
        }
      }
    }
  }
  return true;
}

template <typename DynType>
bool ElfInterface::GetSonameWithTemplate(std::string* soname) {
  if (soname_type_ == SONAME_INVALID) {
    return false;
  }
  if (soname_type_ == SONAME_VALID) {
    *soname = soname_;
    return true;
  }

  soname_type_ = SONAME_INVALID;

  uint64_t soname_offset = 0;
  uint64_t strtab_offset = 0;
  uint64_t strtab_size = 0;

  // Find the soname location from the dynamic headers section.
  DynType dyn;
  uint64_t offset = dynamic_offset_;
  uint64_t max_offset = offset + dynamic_size_;
  for (uint64_t offset = dynamic_offset_; offset < max_offset; offset += sizeof(DynType)) {
    if (!memory_->Read(offset, &dyn, sizeof(dyn))) {
      return false;
    }

    if (dyn.d_tag == DT_STRTAB) {
      strtab_offset = dyn.d_un.d_ptr;
    } else if (dyn.d_tag == DT_STRSZ) {
      strtab_size = dyn.d_un.d_val;
    } else if (dyn.d_tag == DT_SONAME) {
      soname_offset = dyn.d_un.d_val;
    } else if (dyn.d_tag == DT_NULL) {
      break;
    }
  }

  soname_offset += strtab_offset;
  if (soname_offset >= strtab_offset + strtab_size) {
    return false;
  }
  if (!memory_->ReadString(soname_offset, &soname_)) {
    return false;
  }
  soname_type_ = SONAME_VALID;
  *soname = soname_;
  return true;
}

template <typename SymType>
bool ElfInterface::GetFunctionNameWithTemplate(uint64_t addr, std::string* name,
                                               uint64_t* func_offset) {
  if (symbols_.empty()) {
    return false;
  }

  for (const auto symbol : symbols_) {
    if (symbol->GetName<SymType>(addr, load_bias_, memory_, name, func_offset)) {
      return true;
    }
  }
  return false;
}

bool ElfInterface::Step(uint64_t pc, Regs* regs, Memory* process_memory, bool* finished) {
  // Need to subtract off the load_bias to get the correct pc.
  if (pc < load_bias_) {
    return false;
  }
  pc -= load_bias_;

  // Try the eh_frame first.
  DwarfSection* eh_frame = eh_frame_.get();
  if (eh_frame != nullptr && eh_frame->Step(pc, regs, process_memory, finished)) {
    return true;
  }

  // Try the debug_frame next.
  DwarfSection* debug_frame = debug_frame_.get();
  if (debug_frame != nullptr && debug_frame->Step(pc, regs, process_memory, finished)) {
    return true;
  }
  return false;
}

// This is an estimation of the size of the elf file using the location
// of the section headers and size. This assumes that the section headers
// are at the end of the elf file. If the elf has a load bias, the size
// will be too large, but this is acceptable.
template <typename EhdrType>
void ElfInterface::GetMaxSizeWithTemplate(Memory* memory, uint64_t* size) {
  EhdrType ehdr;
  if (!memory->Read(0, &ehdr, sizeof(ehdr))) {
    return;
  }
  if (ehdr.e_shnum == 0) {
    return;
  }
  *size = ehdr.e_shoff + ehdr.e_shentsize * ehdr.e_shnum;
}

// Instantiate all of the needed template functions.
template void ElfInterface::InitHeadersWithTemplate<uint32_t>();
template void ElfInterface::InitHeadersWithTemplate<uint64_t>();

template bool ElfInterface::ReadAllHeaders<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr>();
template bool ElfInterface::ReadAllHeaders<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr>();

template bool ElfInterface::ReadProgramHeaders<Elf32_Ehdr, Elf32_Phdr>(const Elf32_Ehdr&);
template bool ElfInterface::ReadProgramHeaders<Elf64_Ehdr, Elf64_Phdr>(const Elf64_Ehdr&);

template bool ElfInterface::ReadSectionHeaders<Elf32_Ehdr, Elf32_Shdr>(const Elf32_Ehdr&);
template bool ElfInterface::ReadSectionHeaders<Elf64_Ehdr, Elf64_Shdr>(const Elf64_Ehdr&);

template bool ElfInterface::GetSonameWithTemplate<Elf32_Dyn>(std::string*);
template bool ElfInterface::GetSonameWithTemplate<Elf64_Dyn>(std::string*);

template bool ElfInterface::GetFunctionNameWithTemplate<Elf32_Sym>(uint64_t, std::string*,
                                                                   uint64_t*);
template bool ElfInterface::GetFunctionNameWithTemplate<Elf64_Sym>(uint64_t, std::string*,
                                                                   uint64_t*);

template void ElfInterface::GetMaxSizeWithTemplate<Elf32_Ehdr>(Memory*, uint64_t*);
template void ElfInterface::GetMaxSizeWithTemplate<Elf64_Ehdr>(Memory*, uint64_t*);

}  // namespace unwindstack
