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

#include <stdint.h>
#include <stdlib.h>

#include <algorithm>

#include <unwindstack/DwarfStructs.h>
#include <unwindstack/Memory.h>

#include "DwarfDebugFrame.h"
#include "DwarfEncoding.h"
#include "DwarfError.h"

namespace unwindstack {

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::Init(uint64_t offset, uint64_t size) {
  offset_ = offset;
  end_offset_ = offset + size;

  memory_.clear_func_offset();
  memory_.clear_text_offset();
  memory_.set_data_offset(offset);
  memory_.set_cur_offset(offset);

  return CreateSortedFdeList();
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::GetCieInfo(uint8_t* segment_size, uint8_t* encoding) {
  uint8_t version;
  if (!memory_.ReadBytes(&version, 1)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }
  // Read the augmentation string.
  std::vector<char> aug_string;
  char aug_value;
  bool get_encoding = false;
  do {
    if (!memory_.ReadBytes(&aug_value, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    if (aug_value == 'R') {
      get_encoding = true;
    }
    aug_string.push_back(aug_value);
  } while (aug_value != '\0');

  if (version == 4) {
    // Skip the Address Size field.
    memory_.set_cur_offset(memory_.cur_offset() + 1);

    // Read the segment size.
    if (!memory_.ReadBytes(segment_size, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
  } else {
    *segment_size = 0;
  }

  if (aug_string[0] != 'z' || !get_encoding) {
    // No encoding
    return true;
  }

  // Skip code alignment factor
  uint8_t value;
  do {
    if (!memory_.ReadBytes(&value, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
  } while (value & 0x80);

  // Skip data alignment factor
  do {
    if (!memory_.ReadBytes(&value, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
  } while (value & 0x80);

  if (version == 1) {
    // Skip return address register.
    memory_.set_cur_offset(memory_.cur_offset() + 1);
  } else {
    // Skip return address register.
    do {
      if (!memory_.ReadBytes(&value, 1)) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
    } while (value & 0x80);
  }

  // Skip the augmentation length.
  do {
    if (!memory_.ReadBytes(&value, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
  } while (value & 0x80);

  for (size_t i = 1; i < aug_string.size(); i++) {
    if (aug_string[i] == 'R') {
      if (!memory_.ReadBytes(encoding, 1)) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
      // Got the encoding, that's all we are looking for.
      return true;
    } else if (aug_string[i] == 'L') {
      memory_.set_cur_offset(memory_.cur_offset() + 1);
    } else if (aug_string[i] == 'P') {
      uint8_t encoding;
      if (!memory_.ReadBytes(&encoding, 1)) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
      uint64_t value;
      if (!memory_.template ReadEncodedValue<AddressType>(encoding, &value)) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
    }
  }

  // It should be impossible to get here.
  abort();
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::AddFdeInfo(uint64_t entry_offset, uint8_t segment_size,
                                              uint8_t encoding) {
  if (segment_size != 0) {
    memory_.set_cur_offset(memory_.cur_offset() + 1);
  }

  uint64_t start;
  if (!memory_.template ReadEncodedValue<AddressType>(encoding & 0xf, &start)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  uint64_t length;
  if (!memory_.template ReadEncodedValue<AddressType>(encoding & 0xf, &length)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }
  if (length != 0) {
    fdes_.emplace_back(entry_offset, start, length);
  }

  return true;
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::CreateSortedFdeList() {
  memory_.set_cur_offset(offset_);

  // Loop through all of the entries and read just enough to create
  // a sorted list of pcs.
  // This code assumes that first comes the cie, then the fdes that
  // it applies to.
  uint64_t cie_offset = 0;
  uint8_t address_encoding;
  uint8_t segment_size;
  while (memory_.cur_offset() < end_offset_) {
    uint64_t cur_entry_offset = memory_.cur_offset();

    // Figure out the entry length and type.
    uint32_t value32;
    if (!memory_.ReadBytes(&value32, sizeof(value32))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }

    uint64_t next_entry_offset;
    if (value32 == static_cast<uint32_t>(-1)) {
      uint64_t value64;
      if (!memory_.ReadBytes(&value64, sizeof(value64))) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }
      next_entry_offset = memory_.cur_offset() + value64;

      // Read the Cie Id of a Cie or the pointer of the Fde.
      if (!memory_.ReadBytes(&value64, sizeof(value64))) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }

      if (value64 == static_cast<uint64_t>(-1)) {
        // Cie 64 bit
        address_encoding = DW_EH_PE_sdata8;
        if (!GetCieInfo(&segment_size, &address_encoding)) {
          return false;
        }
        cie_offset = cur_entry_offset;
      } else {
        if (offset_ + value64 != cie_offset) {
          // This means that this Fde is not following the Cie.
          last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
          return false;
        }

        // Fde 64 bit
        if (!AddFdeInfo(cur_entry_offset, segment_size, address_encoding)) {
          return false;
        }
      }
    } else {
      next_entry_offset = memory_.cur_offset() + value32;

      // Read the Cie Id of a Cie or the pointer of the Fde.
      if (!memory_.ReadBytes(&value32, sizeof(value32))) {
        last_error_ = DWARF_ERROR_MEMORY_INVALID;
        return false;
      }

      if (value32 == static_cast<uint32_t>(-1)) {
        // Cie 32 bit
        address_encoding = DW_EH_PE_sdata4;
        if (!GetCieInfo(&segment_size, &address_encoding)) {
          return false;
        }
        cie_offset = cur_entry_offset;
      } else {
        if (offset_ + value32 != cie_offset) {
          // This means that this Fde is not following the Cie.
          last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
          return false;
        }

        // Fde 32 bit
        if (!AddFdeInfo(cur_entry_offset, segment_size, address_encoding)) {
          return false;
        }
      }
    }

    if (next_entry_offset < memory_.cur_offset()) {
      // This indicates some kind of corruption, or malformed section data.
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }
    memory_.set_cur_offset(next_entry_offset);
  }

  // Sort the entries.
  std::sort(fdes_.begin(), fdes_.end(), [](const FdeInfo& a, const FdeInfo& b) {
    if (a.start == b.start) return a.end < b.end;
    return a.start < b.start;
  });

  fde_count_ = fdes_.size();

  return true;
}

template <typename AddressType>
bool DwarfDebugFrame<AddressType>::GetFdeOffsetFromPc(uint64_t pc, uint64_t* fde_offset) {
  if (fde_count_ == 0) {
    return false;
  }

  size_t first = 0;
  size_t last = fde_count_;
  while (first < last) {
    size_t current = (first + last) / 2;
    const FdeInfo* info = &fdes_[current];
    if (pc >= info->start && pc <= info->end) {
      *fde_offset = info->offset;
      return true;
    }

    if (pc < info->start) {
      last = current;
    } else {
      first = current + 1;
    }
  }
  return false;
}

template <typename AddressType>
const DwarfFde* DwarfDebugFrame<AddressType>::GetFdeFromIndex(size_t index) {
  if (index >= fdes_.size()) {
    return nullptr;
  }
  return this->GetFdeFromOffset(fdes_[index].offset);
}

// Explicitly instantiate DwarfDebugFrame.
template class DwarfDebugFrame<uint32_t>;
template class DwarfDebugFrame<uint64_t>;

}  // namespace unwindstack
