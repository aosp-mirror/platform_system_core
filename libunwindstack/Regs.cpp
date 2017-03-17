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

#include <assert.h>
#include <elf.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <vector>

#include "Elf.h"
#include "ElfInterface.h"
#include "Machine.h"
#include "MapInfo.h"
#include "Regs.h"
#include "User.h"

template <typename AddressType>
uint64_t RegsTmpl<AddressType>::GetRelPc(Elf* elf, const MapInfo* map_info) {
  uint64_t load_bias = 0;
  if (elf->valid()) {
    load_bias = elf->interface()->load_bias();
  }

  return pc_ - map_info->start + load_bias + map_info->elf_offset;
}

template <typename AddressType>
bool RegsTmpl<AddressType>::GetReturnAddressFromDefault(Memory* memory, uint64_t* value) {
  switch (return_loc_.type) {
  case LOCATION_REGISTER:
    assert(return_loc_.value < total_regs_);
    *value = regs_[return_loc_.value];
    return true;
  case LOCATION_SP_OFFSET:
    AddressType return_value;
    if (!memory->Read(sp_ + return_loc_.value, &return_value, sizeof(return_value))) {
      return false;
    }
    *value = return_value;
    return true;
  case LOCATION_UNKNOWN:
  default:
    return false;
  }
}

RegsArm::RegsArm() : RegsTmpl<uint32_t>(ARM_REG_LAST, ARM_REG_SP,
                                        Location(LOCATION_REGISTER, ARM_REG_LR)) {
}

uint64_t RegsArm::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  uint64_t load_bias = elf->interface()->load_bias();
  if (rel_pc < load_bias) {
    return rel_pc;
  }
  uint64_t adjusted_rel_pc = rel_pc - load_bias;

  if (adjusted_rel_pc < 5) {
    return rel_pc;
  }

  if (adjusted_rel_pc & 1) {
    // This is a thumb instruction, it could be 2 or 4 bytes.
    uint32_t value;
    if (rel_pc < 5 || !elf->memory()->Read(adjusted_rel_pc - 5, &value, sizeof(value)) ||
        (value & 0xe000f000) != 0xe000f000) {
      return rel_pc - 2;
    }
  }
  return rel_pc - 4;
}

RegsArm64::RegsArm64() : RegsTmpl<uint64_t>(ARM64_REG_LAST, ARM64_REG_SP,
                                            Location(LOCATION_REGISTER, ARM64_REG_LR)) {
}

uint64_t RegsArm64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc < 4) {
    return rel_pc;
  }
  return rel_pc - 4;
}

RegsX86::RegsX86() : RegsTmpl<uint32_t>(X86_REG_LAST, X86_REG_SP,
                                        Location(LOCATION_SP_OFFSET, -4)) {
}

uint64_t RegsX86::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc == 0) {
    return 0;
  }
  return rel_pc - 1;
}

RegsX86_64::RegsX86_64() : RegsTmpl<uint64_t>(X86_64_REG_LAST, X86_64_REG_SP,
                                              Location(LOCATION_SP_OFFSET, -8)) {
}

uint64_t RegsX86_64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc == 0) {
    return 0;
  }

  return rel_pc - 1;
}

static Regs* ReadArm(void* remote_data) {
  arm_user_regs* user = reinterpret_cast<arm_user_regs*>(remote_data);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &user->regs[0], ARM_REG_LAST * sizeof(uint32_t));

  regs->set_pc(user->regs[ARM_REG_PC]);
  regs->set_sp(user->regs[ARM_REG_SP]);

  return regs;
}

static Regs* ReadArm64(void* remote_data) {
  arm64_user_regs* user = reinterpret_cast<arm64_user_regs*>(remote_data);

  RegsArm64* regs = new RegsArm64();
  memcpy(regs->RawData(), &user->regs[0], (ARM64_REG_R31 + 1) * sizeof(uint64_t));
  regs->set_pc(user->pc);
  regs->set_sp(user->sp);

  return regs;
}

static Regs* ReadX86(void* remote_data) {
  x86_user_regs* user = reinterpret_cast<x86_user_regs*>(remote_data);

  RegsX86* regs = new RegsX86();
  (*regs)[X86_REG_EAX] = user->eax;
  (*regs)[X86_REG_EBX] = user->ebx;
  (*regs)[X86_REG_ECX] = user->ecx;
  (*regs)[X86_REG_EDX] = user->edx;
  (*regs)[X86_REG_EBP] = user->ebp;
  (*regs)[X86_REG_EDI] = user->edi;
  (*regs)[X86_REG_ESI] = user->esi;
  (*regs)[X86_REG_ESP] = user->esp;
  (*regs)[X86_REG_EIP] = user->eip;

  regs->set_pc(user->eip);
  regs->set_sp(user->esp);

  return regs;
}

static Regs* ReadX86_64(void* remote_data) {
  x86_64_user_regs* user = reinterpret_cast<x86_64_user_regs*>(remote_data);

  RegsX86_64* regs = new RegsX86_64();
  (*regs)[X86_64_REG_RAX] = user->rax;
  (*regs)[X86_64_REG_RBX] = user->rbx;
  (*regs)[X86_64_REG_RCX] = user->rcx;
  (*regs)[X86_64_REG_RDX] = user->rdx;
  (*regs)[X86_64_REG_R8] = user->r8;
  (*regs)[X86_64_REG_R9] = user->r9;
  (*regs)[X86_64_REG_R10] = user->r10;
  (*regs)[X86_64_REG_R11] = user->r11;
  (*regs)[X86_64_REG_R12] = user->r12;
  (*regs)[X86_64_REG_R13] = user->r13;
  (*regs)[X86_64_REG_R14] = user->r14;
  (*regs)[X86_64_REG_R15] = user->r15;
  (*regs)[X86_64_REG_RDI] = user->rdi;
  (*regs)[X86_64_REG_RSI] = user->rsi;
  (*regs)[X86_64_REG_RBP] = user->rbp;
  (*regs)[X86_64_REG_RSP] = user->rsp;
  (*regs)[X86_64_REG_RIP] = user->rip;

  regs->set_pc(user->rip);
  regs->set_sp(user->rsp);

  return regs;
}

// This function assumes that reg_data is already aligned to a 64 bit value.
// If not this could crash with an unaligned access.
Regs* Regs::RemoteGet(pid_t pid, uint32_t* machine_type) {
  // Make the buffer large enough to contain the largest registers type.
  std::vector<uint64_t> buffer(MAX_USER_REGS_SIZE / sizeof(uint64_t));
  struct iovec io;
  io.iov_base = buffer.data();
  io.iov_len = buffer.size() * sizeof(uint64_t);

  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, reinterpret_cast<void*>(&io)) == -1) {
    return nullptr;
  }

  switch (io.iov_len) {
  case sizeof(x86_user_regs):
    *machine_type = EM_386;
    return ReadX86(buffer.data());
  case sizeof(x86_64_user_regs):
    *machine_type = EM_X86_64;
    return ReadX86_64(buffer.data());
  case sizeof(arm_user_regs):
    *machine_type = EM_ARM;
    return ReadArm(buffer.data());
  case sizeof(arm64_user_regs):
    *machine_type = EM_AARCH64;
    return ReadArm64(buffer.data());
  }
  return nullptr;
}
