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

#ifndef _LIBUNWINDSTACK_REGS_H
#define _LIBUNWINDSTACK_REGS_H

#include <stdint.h>

#include <vector>

// Forward declarations.
class Elf;
struct MapInfo;

class Regs {
 public:
  enum LocationEnum : uint8_t {
    LOCATION_UNKNOWN = 0,
    LOCATION_REGISTER,
    LOCATION_SP_OFFSET,
  };

  struct Location {
    Location(LocationEnum type, int16_t value) : type(type), value(value) {}

    LocationEnum type;
    int16_t value;
  };

  Regs(uint16_t total_regs, uint16_t sp_reg, const Location& return_loc)
      : total_regs_(total_regs), sp_reg_(sp_reg), return_loc_(return_loc) {}
  virtual ~Regs() = default;

  virtual void* RawData() = 0;
  virtual uint64_t pc() = 0;
  virtual uint64_t sp() = 0;

  virtual bool GetReturnAddressFromDefault(Memory* memory, uint64_t* value) = 0;

  virtual uint64_t GetRelPc(Elf* elf, const MapInfo* map_info) = 0;

  virtual uint64_t GetAdjustedPc(uint64_t rel_pc, Elf* elf) = 0;

  uint16_t sp_reg() { return sp_reg_; }
  uint16_t total_regs() { return total_regs_; }

  static Regs* RemoteGet(pid_t pid, uint32_t* machine_type);

 protected:
  uint16_t total_regs_;
  uint16_t sp_reg_;
  Location return_loc_;
};

template <typename AddressType>
class RegsTmpl : public Regs {
 public:
  RegsTmpl(uint16_t total_regs, uint16_t sp_reg, Location return_loc)
      : Regs(total_regs, sp_reg, return_loc), regs_(total_regs) {}
  virtual ~RegsTmpl() = default;

  uint64_t GetRelPc(Elf* elf, const MapInfo* map_info) override;

  bool GetReturnAddressFromDefault(Memory* memory, uint64_t* value) override;

  uint64_t pc() override { return pc_; }
  uint64_t sp() override { return sp_; }

  void set_pc(AddressType pc) { pc_ = pc; }
  void set_sp(AddressType sp) { sp_ = sp; }

  inline AddressType& operator[](size_t reg) { return regs_[reg]; }

  void* RawData() override { return regs_.data(); }

 protected:
  AddressType pc_;
  AddressType sp_;
  std::vector<AddressType> regs_;
};

class RegsArm : public RegsTmpl<uint32_t> {
 public:
  RegsArm();
  virtual ~RegsArm() = default;

  uint64_t GetAdjustedPc(uint64_t rel_pc, Elf* elf) override;
};

class RegsArm64 : public RegsTmpl<uint64_t> {
 public:
  RegsArm64();
  virtual ~RegsArm64() = default;

  uint64_t GetAdjustedPc(uint64_t rel_pc, Elf* elf) override;
};

class RegsX86 : public RegsTmpl<uint32_t> {
 public:
  RegsX86();
  virtual ~RegsX86() = default;

  uint64_t GetAdjustedPc(uint64_t rel_pc, Elf* elf) override;
};

class RegsX86_64 : public RegsTmpl<uint64_t> {
 public:
  RegsX86_64();
  virtual ~RegsX86_64() = default;

  uint64_t GetAdjustedPc(uint64_t rel_pc, Elf* elf) override;
};

#endif  // _LIBUNWINDSTACK_REGS_H
