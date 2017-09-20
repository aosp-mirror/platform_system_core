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

#include <unwindstack/DwarfLocation.h>
#include <unwindstack/DwarfMemory.h>
#include <unwindstack/DwarfSection.h>
#include <unwindstack/DwarfStructs.h>
#include <unwindstack/Log.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>

#include "DwarfCfa.h"
#include "DwarfEncoding.h"
#include "DwarfError.h"
#include "DwarfOp.h"

namespace unwindstack {

DwarfSection::DwarfSection(Memory* memory) : memory_(memory), last_error_(DWARF_ERROR_NONE) {}

const DwarfFde* DwarfSection::GetFdeFromPc(uint64_t pc) {
  uint64_t fde_offset;
  if (!GetFdeOffsetFromPc(pc, &fde_offset)) {
    return nullptr;
  }
  const DwarfFde* fde = GetFdeFromOffset(fde_offset);
  // Guaranteed pc >= pc_start, need to check pc in the fde range.
  if (pc < fde->pc_end) {
    return fde;
  }
  last_error_ = DWARF_ERROR_ILLEGAL_STATE;
  return nullptr;
}

bool DwarfSection::Step(uint64_t pc, Regs* regs, Memory* process_memory, bool* finished) {
  last_error_ = DWARF_ERROR_NONE;
  const DwarfFde* fde = GetFdeFromPc(pc);
  if (fde == nullptr || fde->cie == nullptr) {
    last_error_ = DWARF_ERROR_ILLEGAL_STATE;
    return false;
  }

  // Now get the location information for this pc.
  dwarf_loc_regs_t loc_regs;
  if (!GetCfaLocationInfo(pc, fde, &loc_regs)) {
    return false;
  }

  // Now eval the actual registers.
  return Eval(fde->cie, process_memory, loc_regs, regs, finished);
}

template <typename AddressType>
bool DwarfSectionImpl<AddressType>::EvalExpression(const DwarfLocation& loc, uint8_t version,
                                                   Memory* regular_memory, AddressType* value) {
  DwarfOp<AddressType> op(&memory_, regular_memory);

  // Need to evaluate the op data.
  uint64_t start = loc.values[1];
  uint64_t end = start + loc.values[0];
  if (!op.Eval(start, end, version)) {
    last_error_ = op.last_error();
    return false;
  }
  if (op.StackSize() == 0) {
    last_error_ = DWARF_ERROR_ILLEGAL_STATE;
    return false;
  }
  // We don't support an expression that evaluates to a register number.
  if (op.is_register()) {
    last_error_ = DWARF_ERROR_NOT_IMPLEMENTED;
    return false;
  }
  *value = op.StackAt(0);
  return true;
}

template <typename AddressType>
bool DwarfSectionImpl<AddressType>::Eval(const DwarfCie* cie, Memory* regular_memory,
                                         const dwarf_loc_regs_t& loc_regs, Regs* regs,
                                         bool* finished) {
  RegsImpl<AddressType>* cur_regs = reinterpret_cast<RegsImpl<AddressType>*>(regs);
  if (cie->return_address_register >= cur_regs->total_regs()) {
    last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
    return false;
  }

  // Get the cfa value;
  auto cfa_entry = loc_regs.find(CFA_REG);
  if (cfa_entry == loc_regs.end()) {
    last_error_ = DWARF_ERROR_CFA_NOT_DEFINED;
    return false;
  }

  AddressType prev_pc = regs->pc();
  AddressType prev_cfa = regs->sp();

  AddressType cfa;
  const DwarfLocation* loc = &cfa_entry->second;
  // Only a few location types are valid for the cfa.
  switch (loc->type) {
    case DWARF_LOCATION_REGISTER:
      if (loc->values[0] >= cur_regs->total_regs()) {
        last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
        return false;
      }
      // If the stack pointer register is the CFA, and the stack
      // pointer register does not have any associated location
      // information, use the current cfa value.
      if (regs->sp_reg() == loc->values[0] && loc_regs.count(regs->sp_reg()) == 0) {
        cfa = prev_cfa;
      } else {
        cfa = (*cur_regs)[loc->values[0]];
      }
      cfa += loc->values[1];
      break;
    case DWARF_LOCATION_EXPRESSION:
    case DWARF_LOCATION_VAL_EXPRESSION: {
      AddressType value;
      if (!EvalExpression(*loc, cie->version, regular_memory, &value)) {
        return false;
      }
      if (loc->type == DWARF_LOCATION_EXPRESSION) {
        if (!regular_memory->Read(value, &cfa, sizeof(AddressType))) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
      } else {
        cfa = value;
      }
      break;
    }
    default:
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
  }

  // This code is not guaranteed to work in cases where a register location
  // is a double indirection to the actual value. For example, if r3 is set
  // to r5 + 4, and r5 is set to CFA + 4, then this won't necessarily work
  // because it does not guarantee that r5 is evaluated before r3.
  // Check that this case does not exist, and error if it does.
  bool return_address_undefined = false;
  for (const auto& entry : loc_regs) {
    uint16_t reg = entry.first;
    // Already handled the CFA register.
    if (reg == CFA_REG) continue;

    if (reg >= cur_regs->total_regs()) {
      // Skip this unknown register.
      continue;
    }

    const DwarfLocation* loc = &entry.second;
    switch (loc->type) {
      case DWARF_LOCATION_OFFSET:
        if (!regular_memory->Read(cfa + loc->values[0], &(*cur_regs)[reg], sizeof(AddressType))) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
        break;
      case DWARF_LOCATION_VAL_OFFSET:
        (*cur_regs)[reg] = cfa + loc->values[0];
        break;
      case DWARF_LOCATION_REGISTER: {
        uint16_t cur_reg = loc->values[0];
        if (cur_reg >= cur_regs->total_regs()) {
          last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
          return false;
        }
        if (loc_regs.find(cur_reg) != loc_regs.end()) {
          // This is a double indirection, a register definition references
          // another register which is also defined as something other
          // than a register.
          log(0,
              "Invalid indirection: register %d references register %d which is "
              "not a plain register.\n",
              reg, cur_reg);
          last_error_ = DWARF_ERROR_ILLEGAL_STATE;
          return false;
        }
        (*cur_regs)[reg] = (*cur_regs)[cur_reg] + loc->values[1];
        break;
      }
      case DWARF_LOCATION_EXPRESSION:
      case DWARF_LOCATION_VAL_EXPRESSION: {
        AddressType value;
        if (!EvalExpression(*loc, cie->version, regular_memory, &value)) {
          return false;
        }
        if (loc->type == DWARF_LOCATION_EXPRESSION) {
          if (!regular_memory->Read(value, &(*cur_regs)[reg], sizeof(AddressType))) {
            last_error_ = DWARF_ERROR_MEMORY_INVALID;
            return false;
          }
        } else {
          (*cur_regs)[reg] = value;
        }
        break;
      }
      case DWARF_LOCATION_UNDEFINED:
        if (reg == cie->return_address_register) {
          return_address_undefined = true;
        }
      default:
        break;
    }
  }

  // Find the return address location.
  if (return_address_undefined) {
    cur_regs->set_pc(0);
    *finished = true;
  } else {
    cur_regs->set_pc((*cur_regs)[cie->return_address_register]);
    *finished = false;
  }
  cur_regs->set_sp(cfa);
  // Return false if the unwind is not finished or the cfa and pc didn't change.
  return *finished || prev_cfa != cfa || prev_pc != cur_regs->pc();
}

template <typename AddressType>
const DwarfCie* DwarfSectionImpl<AddressType>::GetCie(uint64_t offset) {
  auto cie_entry = cie_entries_.find(offset);
  if (cie_entry != cie_entries_.end()) {
    return &cie_entry->second;
  }
  DwarfCie* cie = &cie_entries_[offset];
  memory_.set_cur_offset(offset);
  if (!FillInCie(cie)) {
    // Erase the cached entry.
    cie_entries_.erase(offset);
    return nullptr;
  }
  return cie;
}

template <typename AddressType>
bool DwarfSectionImpl<AddressType>::FillInCie(DwarfCie* cie) {
  uint32_t length32;
  if (!memory_.ReadBytes(&length32, sizeof(length32))) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }
  // Set the default for the lsda encoding.
  cie->lsda_encoding = DW_EH_PE_omit;

  if (length32 == static_cast<uint32_t>(-1)) {
    // 64 bit Cie
    uint64_t length64;
    if (!memory_.ReadBytes(&length64, sizeof(length64))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }

    cie->cfa_instructions_end = memory_.cur_offset() + length64;
    cie->fde_address_encoding = DW_EH_PE_sdata8;

    uint64_t cie_id;
    if (!memory_.ReadBytes(&cie_id, sizeof(cie_id))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    if (!IsCie64(cie_id)) {
      // This is not a Cie, something has gone horribly wrong.
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }
  } else {
    // 32 bit Cie
    cie->cfa_instructions_end = memory_.cur_offset() + length32;
    cie->fde_address_encoding = DW_EH_PE_sdata4;

    uint32_t cie_id;
    if (!memory_.ReadBytes(&cie_id, sizeof(cie_id))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    if (!IsCie32(cie_id)) {
      // This is not a Cie, something has gone horribly wrong.
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }
  }

  if (!memory_.ReadBytes(&cie->version, sizeof(cie->version))) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  if (cie->version != 1 && cie->version != 3 && cie->version != 4) {
    // Unrecognized version.
    last_error_ = DWARF_ERROR_UNSUPPORTED_VERSION;
    return false;
  }

  // Read the augmentation string.
  char aug_value;
  do {
    if (!memory_.ReadBytes(&aug_value, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    cie->augmentation_string.push_back(aug_value);
  } while (aug_value != '\0');

  if (cie->version == 4) {
    // Skip the Address Size field since we only use it for validation.
    memory_.set_cur_offset(memory_.cur_offset() + 1);

    // Segment Size
    if (!memory_.ReadBytes(&cie->segment_size, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
  }

  // Code Alignment Factor
  if (!memory_.ReadULEB128(&cie->code_alignment_factor)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  // Data Alignment Factor
  if (!memory_.ReadSLEB128(&cie->data_alignment_factor)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  if (cie->version == 1) {
    // Return Address is a single byte.
    uint8_t return_address_register;
    if (!memory_.ReadBytes(&return_address_register, 1)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    cie->return_address_register = return_address_register;
  } else if (!memory_.ReadULEB128(&cie->return_address_register)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  if (cie->augmentation_string[0] != 'z') {
    cie->cfa_instructions_offset = memory_.cur_offset();
    return true;
  }

  uint64_t aug_length;
  if (!memory_.ReadULEB128(&aug_length)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }
  cie->cfa_instructions_offset = memory_.cur_offset() + aug_length;

  for (size_t i = 1; i < cie->augmentation_string.size(); i++) {
    switch (cie->augmentation_string[i]) {
      case 'L':
        if (!memory_.ReadBytes(&cie->lsda_encoding, 1)) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
        break;
      case 'P': {
        uint8_t encoding;
        if (!memory_.ReadBytes(&encoding, 1)) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
        if (!memory_.ReadEncodedValue<AddressType>(encoding, &cie->personality_handler)) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
      } break;
      case 'R':
        if (!memory_.ReadBytes(&cie->fde_address_encoding, 1)) {
          last_error_ = DWARF_ERROR_MEMORY_INVALID;
          return false;
        }
        break;
    }
  }
  return true;
}

template <typename AddressType>
const DwarfFde* DwarfSectionImpl<AddressType>::GetFdeFromOffset(uint64_t offset) {
  auto fde_entry = fde_entries_.find(offset);
  if (fde_entry != fde_entries_.end()) {
    return &fde_entry->second;
  }
  DwarfFde* fde = &fde_entries_[offset];
  memory_.set_cur_offset(offset);
  if (!FillInFde(fde)) {
    fde_entries_.erase(offset);
    return nullptr;
  }
  return fde;
}

template <typename AddressType>
bool DwarfSectionImpl<AddressType>::FillInFde(DwarfFde* fde) {
  uint32_t length32;
  if (!memory_.ReadBytes(&length32, sizeof(length32))) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }

  if (length32 == static_cast<uint32_t>(-1)) {
    // 64 bit Fde.
    uint64_t length64;
    if (!memory_.ReadBytes(&length64, sizeof(length64))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    fde->cfa_instructions_end = memory_.cur_offset() + length64;

    uint64_t value64;
    if (!memory_.ReadBytes(&value64, sizeof(value64))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    if (IsCie64(value64)) {
      // This is a Cie, this means something has gone wrong.
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    // Get the Cie pointer, which is necessary to properly read the rest of
    // of the Fde information.
    fde->cie_offset = GetCieOffsetFromFde64(value64);
  } else {
    // 32 bit Fde.
    fde->cfa_instructions_end = memory_.cur_offset() + length32;

    uint32_t value32;
    if (!memory_.ReadBytes(&value32, sizeof(value32))) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    if (IsCie32(value32)) {
      // This is a Cie, this means something has gone wrong.
      last_error_ = DWARF_ERROR_ILLEGAL_VALUE;
      return false;
    }

    // Get the Cie pointer, which is necessary to properly read the rest of
    // of the Fde information.
    fde->cie_offset = GetCieOffsetFromFde32(value32);
  }
  uint64_t cur_offset = memory_.cur_offset();

  const DwarfCie* cie = GetCie(fde->cie_offset);
  if (cie == nullptr) {
    return false;
  }
  fde->cie = cie;

  if (cie->segment_size != 0) {
    // Skip over the segment selector for now.
    cur_offset += cie->segment_size;
  }
  memory_.set_cur_offset(cur_offset);

  if (!memory_.ReadEncodedValue<AddressType>(cie->fde_address_encoding & 0xf, &fde->pc_start)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }
  fde->pc_start = AdjustPcFromFde(fde->pc_start);

  if (!memory_.ReadEncodedValue<AddressType>(cie->fde_address_encoding & 0xf, &fde->pc_end)) {
    last_error_ = DWARF_ERROR_MEMORY_INVALID;
    return false;
  }
  fde->pc_end += fde->pc_start;
  if (cie->augmentation_string.size() > 0 && cie->augmentation_string[0] == 'z') {
    // Augmentation Size
    uint64_t aug_length;
    if (!memory_.ReadULEB128(&aug_length)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }
    uint64_t cur_offset = memory_.cur_offset();

    if (!memory_.ReadEncodedValue<AddressType>(cie->lsda_encoding, &fde->lsda_address)) {
      last_error_ = DWARF_ERROR_MEMORY_INVALID;
      return false;
    }

    // Set our position to after all of the augmentation data.
    memory_.set_cur_offset(cur_offset + aug_length);
  }
  fde->cfa_instructions_offset = memory_.cur_offset();

  return true;
}

template <typename AddressType>
bool DwarfSectionImpl<AddressType>::GetCfaLocationInfo(uint64_t pc, const DwarfFde* fde,
                                                       dwarf_loc_regs_t* loc_regs) {
  DwarfCfa<AddressType> cfa(&memory_, fde);

  // Look for the cached copy of the cie data.
  auto reg_entry = cie_loc_regs_.find(fde->cie_offset);
  if (reg_entry == cie_loc_regs_.end()) {
    if (!cfa.GetLocationInfo(pc, fde->cie->cfa_instructions_offset, fde->cie->cfa_instructions_end,
                             loc_regs)) {
      last_error_ = cfa.last_error();
      return false;
    }
    cie_loc_regs_[fde->cie_offset] = *loc_regs;
  }
  cfa.set_cie_loc_regs(&cie_loc_regs_[fde->cie_offset]);
  if (!cfa.GetLocationInfo(pc, fde->cfa_instructions_offset, fde->cfa_instructions_end, loc_regs)) {
    last_error_ = cfa.last_error();
    return false;
  }
  return true;
}

template <typename AddressType>
bool DwarfSectionImpl<AddressType>::Log(uint8_t indent, uint64_t pc, uint64_t load_bias,
                                        const DwarfFde* fde) {
  DwarfCfa<AddressType> cfa(&memory_, fde);

  // Always print the cie information.
  const DwarfCie* cie = fde->cie;
  if (!cfa.Log(indent, pc, load_bias, cie->cfa_instructions_offset, cie->cfa_instructions_end)) {
    last_error_ = cfa.last_error();
    return false;
  }
  if (!cfa.Log(indent, pc, load_bias, fde->cfa_instructions_offset, fde->cfa_instructions_end)) {
    last_error_ = cfa.last_error();
    return false;
  }
  return true;
}

// Explicitly instantiate DwarfSectionImpl
template class DwarfSectionImpl<uint32_t>;
template class DwarfSectionImpl<uint64_t>;

}  // namespace unwindstack
