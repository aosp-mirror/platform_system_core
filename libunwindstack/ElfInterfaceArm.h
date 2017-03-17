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

#ifndef _LIBUNWINDSTACK_ELF_INTERFACE_ARM_H
#define _LIBUNWINDSTACK_ELF_INTERFACE_ARM_H

#include <elf.h>
#include <stdint.h>

#include <iterator>
#include <unordered_map>

#include "ElfInterface.h"
#include "Memory.h"

class ElfInterfaceArm : public ElfInterface32 {
 public:
  ElfInterfaceArm(Memory* memory) : ElfInterface32(memory) {}
  virtual ~ElfInterfaceArm() = default;

  class iterator : public std::iterator<std::bidirectional_iterator_tag, uint32_t> {
   public:
    iterator(ElfInterfaceArm* interface, size_t index) : interface_(interface), index_(index) { }

    iterator& operator++() { index_++; return *this; }
    iterator& operator++(int increment) { index_ += increment; return *this; }
    iterator& operator--() { index_--; return *this; }
    iterator& operator--(int decrement) { index_ -= decrement; return *this; }

    bool operator==(const iterator& rhs) { return this->index_ == rhs.index_; }
    bool operator!=(const iterator& rhs) { return this->index_ != rhs.index_; }

    uint32_t operator*() {
      uint32_t addr = interface_->addrs_[index_];
      if (addr == 0) {
        if (!interface_->GetPrel31Addr(interface_->start_offset_ + index_ * 8, &addr)) {
          return 0;
        }
        interface_->addrs_[index_] = addr;
      }
      return addr;
    }

   private:
    ElfInterfaceArm* interface_ = nullptr;
    size_t index_ = 0;
  };

  iterator begin() { return iterator(this, 0); }
  iterator end() { return iterator(this, total_entries_); }

  bool GetPrel31Addr(uint32_t offset, uint32_t* addr);

  bool FindEntry(uint32_t pc, uint64_t* entry_offset);

  bool HandleType(uint64_t offset, uint32_t type) override;

  bool Step(uint64_t pc, Regs* regs, Memory* process_memory) override;

  bool StepExidx(uint64_t pc, Regs* regs, Memory* process_memory);

  uint64_t start_offset() { return start_offset_; }

  void set_start_offset(uint64_t start_offset) { start_offset_ = start_offset; }

  size_t total_entries() { return total_entries_; }

  void set_total_entries(size_t total_entries) { total_entries_ = total_entries; }

 private:
  uint64_t start_offset_ = 0;
  size_t total_entries_ = 0;

  std::unordered_map<size_t, uint32_t> addrs_;
};

#endif  // _LIBUNWINDSTACK_ELF_INTERFACE_ARM_H
