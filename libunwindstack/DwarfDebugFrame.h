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

#ifndef _LIBUNWINDSTACK_DWARF_DEBUG_FRAME_H
#define _LIBUNWINDSTACK_DWARF_DEBUG_FRAME_H

#include <stdint.h>

#include <vector>

#include <unwindstack/DwarfSection.h>

namespace unwindstack {

template <typename AddressType>
class DwarfDebugFrame : public DwarfSectionImpl<AddressType> {
 public:
  // Add these so that the protected members of DwarfSectionImpl
  // can be accessed without needing a this->.
  using DwarfSectionImpl<AddressType>::memory_;
  using DwarfSectionImpl<AddressType>::fde_count_;
  using DwarfSectionImpl<AddressType>::last_error_;

  struct FdeInfo {
    FdeInfo(uint64_t offset, uint64_t start, uint64_t length)
        : offset(offset), start(start), end(start + length) {}

    uint64_t offset;
    AddressType start;
    AddressType end;
  };

  DwarfDebugFrame(Memory* memory) : DwarfSectionImpl<AddressType>(memory) {}
  virtual ~DwarfDebugFrame() = default;

  bool Init(uint64_t offset, uint64_t size) override;

  bool GetFdeOffsetFromPc(uint64_t pc, uint64_t* fde_offset) override;

  const DwarfFde* GetFdeFromIndex(size_t index) override;

  bool IsCie32(uint32_t value32) override { return value32 == static_cast<uint32_t>(-1); }

  bool IsCie64(uint64_t value64) override { return value64 == static_cast<uint64_t>(-1); }

  uint64_t GetCieOffsetFromFde32(uint32_t pointer) override { return offset_ + pointer; }

  uint64_t GetCieOffsetFromFde64(uint64_t pointer) override { return offset_ + pointer; }

  uint64_t AdjustPcFromFde(uint64_t pc) override { return pc; }

  bool GetCieInfo(uint8_t* segment_size, uint8_t* encoding);

  bool AddFdeInfo(uint64_t entry_offset, uint8_t segment_size, uint8_t encoding);

  bool CreateSortedFdeList();

 protected:
  uint64_t offset_;
  uint64_t end_offset_;

  std::vector<FdeInfo> fdes_;
};

}  // namespace unwindstack

#endif  // _LIBUNWINDSTACK_DWARF_DEBUG_FRAME_H
