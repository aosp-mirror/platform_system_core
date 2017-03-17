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

#ifndef _LIBUNWINDSTACK_ELF_INTERFACE_H
#define _LIBUNWINDSTACK_ELF_INTERFACE_H

#include <elf.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// Forward declarations.
class Memory;
class Regs;

struct LoadInfo {
  uint64_t offset;
  uint64_t table_offset;
  size_t table_size;
};

enum : uint8_t {
  SONAME_UNKNOWN = 0,
  SONAME_VALID,
  SONAME_INVALID,
};

class ElfInterface {
 public:
  ElfInterface(Memory* memory) : memory_(memory) {}
  virtual ~ElfInterface() = default;

  virtual bool Init() = 0;

  virtual void InitHeaders() = 0;

  virtual bool GetSoname(std::string* name) = 0;

  virtual bool GetFunctionName(uint64_t addr, std::string* name, uint64_t* offset) = 0;

  virtual bool Step(uint64_t rel_pc, Regs* regs, Memory* process_memory);

  Memory* CreateGnuDebugdataMemory();

  Memory* memory() { return memory_; }

  const std::unordered_map<uint64_t, LoadInfo>& pt_loads() { return pt_loads_; }
  uint64_t load_bias() { return load_bias_; }
  void set_load_bias(uint64_t load_bias) { load_bias_ = load_bias; }

  uint64_t dynamic_offset() { return dynamic_offset_; }
  uint64_t dynamic_size() { return dynamic_size_; }
  uint64_t eh_frame_offset() { return eh_frame_offset_; }
  uint64_t eh_frame_size() { return eh_frame_size_; }
  uint64_t gnu_debugdata_offset() { return gnu_debugdata_offset_; }
  uint64_t gnu_debugdata_size() { return gnu_debugdata_size_; }

 protected:
  template <typename EhdrType, typename PhdrType, typename ShdrType>
  bool ReadAllHeaders();

  template <typename EhdrType, typename PhdrType>
  bool ReadProgramHeaders(const EhdrType& ehdr);

  template <typename EhdrType, typename ShdrType>
  bool ReadSectionHeaders(const EhdrType& ehdr);

  template <typename DynType>
  bool GetSonameWithTemplate(std::string* soname);

  virtual bool HandleType(uint64_t, uint32_t) { return false; }

  Memory* memory_;
  std::unordered_map<uint64_t, LoadInfo> pt_loads_;
  uint64_t load_bias_ = 0;

  // Stored elf data.
  uint64_t dynamic_offset_ = 0;
  uint64_t dynamic_size_ = 0;

  uint64_t eh_frame_offset_ = 0;
  uint64_t eh_frame_size_ = 0;

  uint64_t debug_frame_offset_ = 0;
  uint64_t debug_frame_size_ = 0;

  uint64_t gnu_debugdata_offset_ = 0;
  uint64_t gnu_debugdata_size_ = 0;

  uint8_t soname_type_ = SONAME_UNKNOWN;
  std::string soname_;
};

class ElfInterface32 : public ElfInterface {
 public:
  ElfInterface32(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterface32() = default;

  bool Init() override {
    return ElfInterface::ReadAllHeaders<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr>();
  }

  void InitHeaders() override {
  }

  bool GetSoname(std::string* soname) override {
    return ElfInterface::GetSonameWithTemplate<Elf32_Dyn>(soname);
  }

  bool GetFunctionName(uint64_t, std::string*, uint64_t*) override {
    return false;
  }
};

class ElfInterface64 : public ElfInterface {
 public:
  ElfInterface64(Memory* memory) : ElfInterface(memory) {}
  virtual ~ElfInterface64() = default;

  bool Init() override {
    return ElfInterface::ReadAllHeaders<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr>();
  }

  void InitHeaders() override {
  }

  bool GetSoname(std::string* soname) override {
    return ElfInterface::GetSonameWithTemplate<Elf64_Dyn>(soname);
  }

  bool GetFunctionName(uint64_t, std::string*, uint64_t*) override {
    return false;
  }
};

#endif  // _LIBUNWINDSTACK_ELF_INTERFACE_H
