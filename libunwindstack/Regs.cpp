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
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>

#include <vector>

#include "Check.h"
#include "Elf.h"
#include "ElfInterface.h"
#include "Machine.h"
#include "MapInfo.h"
#include "Regs.h"
#include "Ucontext.h"
#include "User.h"

template <typename AddressType>
uint64_t RegsImpl<AddressType>::GetRelPc(Elf* elf, const MapInfo* map_info) {
  uint64_t load_bias = 0;
  if (elf->valid()) {
    load_bias = elf->interface()->load_bias();
  }

  return pc_ - map_info->start + load_bias + map_info->elf_offset;
}

template <typename AddressType>
bool RegsImpl<AddressType>::GetReturnAddressFromDefault(Memory* memory, uint64_t* value) {
  switch (return_loc_.type) {
  case LOCATION_REGISTER:
    CHECK(return_loc_.value < total_regs_);
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

RegsArm::RegsArm()
    : RegsImpl<uint32_t>(ARM_REG_LAST, ARM_REG_SP, Location(LOCATION_REGISTER, ARM_REG_LR)) {}

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

void RegsArm::SetFromRaw() {
  set_pc(regs_[ARM_REG_PC]);
  set_sp(regs_[ARM_REG_SP]);
}

RegsArm64::RegsArm64()
    : RegsImpl<uint64_t>(ARM64_REG_LAST, ARM64_REG_SP, Location(LOCATION_REGISTER, ARM64_REG_LR)) {}

uint64_t RegsArm64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc < 4) {
    return rel_pc;
  }
  return rel_pc - 4;
}

void RegsArm64::SetFromRaw() {
  set_pc(regs_[ARM64_REG_PC]);
  set_sp(regs_[ARM64_REG_SP]);
}

RegsX86::RegsX86()
    : RegsImpl<uint32_t>(X86_REG_LAST, X86_REG_SP, Location(LOCATION_SP_OFFSET, -4)) {}

uint64_t RegsX86::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc == 0) {
    return 0;
  }
  return rel_pc - 1;
}

void RegsX86::SetFromRaw() {
  set_pc(regs_[X86_REG_PC]);
  set_sp(regs_[X86_REG_SP]);
}

RegsX86_64::RegsX86_64()
    : RegsImpl<uint64_t>(X86_64_REG_LAST, X86_64_REG_SP, Location(LOCATION_SP_OFFSET, -8)) {}

uint64_t RegsX86_64::GetAdjustedPc(uint64_t rel_pc, Elf* elf) {
  if (!elf->valid()) {
    return rel_pc;
  }

  if (rel_pc == 0) {
    return 0;
  }

  return rel_pc - 1;
}

void RegsX86_64::SetFromRaw() {
  set_pc(regs_[X86_64_REG_PC]);
  set_sp(regs_[X86_64_REG_SP]);
}

static Regs* ReadArm(void* remote_data) {
  arm_user_regs* user = reinterpret_cast<arm_user_regs*>(remote_data);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &user->regs[0], ARM_REG_LAST * sizeof(uint32_t));
  regs->SetFromRaw();
  return regs;
}

static Regs* ReadArm64(void* remote_data) {
  arm64_user_regs* user = reinterpret_cast<arm64_user_regs*>(remote_data);

  RegsArm64* regs = new RegsArm64();
  memcpy(regs->RawData(), &user->regs[0], (ARM64_REG_R31 + 1) * sizeof(uint64_t));
  uint64_t* reg_data = reinterpret_cast<uint64_t*>(regs->RawData());
  reg_data[ARM64_REG_PC] = user->pc;
  reg_data[ARM64_REG_SP] = user->sp;
  regs->SetFromRaw();
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

  regs->SetFromRaw();
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

  regs->SetFromRaw();
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

static Regs* CreateFromArmUcontext(void* ucontext) {
  arm_ucontext_t* arm_ucontext = reinterpret_cast<arm_ucontext_t*>(ucontext);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &arm_ucontext->uc_mcontext.regs[0], ARM_REG_LAST * sizeof(uint32_t));
  regs->SetFromRaw();
  return regs;
}

static Regs* CreateFromArm64Ucontext(void* ucontext) {
  arm64_ucontext_t* arm64_ucontext = reinterpret_cast<arm64_ucontext_t*>(ucontext);

  RegsArm64* regs = new RegsArm64();
  memcpy(regs->RawData(), &arm64_ucontext->uc_mcontext.regs[0], ARM64_REG_LAST * sizeof(uint64_t));
  regs->SetFromRaw();
  return regs;
}

static Regs* CreateFromX86Ucontext(void* ucontext) {
  x86_ucontext_t* x86_ucontext = reinterpret_cast<x86_ucontext_t*>(ucontext);

  RegsX86* regs = new RegsX86();
  // Put the registers in the expected order.
  (*regs)[X86_REG_GS] = x86_ucontext->uc_mcontext.gs;
  (*regs)[X86_REG_FS] = x86_ucontext->uc_mcontext.fs;
  (*regs)[X86_REG_ES] = x86_ucontext->uc_mcontext.es;
  (*regs)[X86_REG_DS] = x86_ucontext->uc_mcontext.ds;
  (*regs)[X86_REG_EDI] = x86_ucontext->uc_mcontext.edi;
  (*regs)[X86_REG_ESI] = x86_ucontext->uc_mcontext.esi;
  (*regs)[X86_REG_EBP] = x86_ucontext->uc_mcontext.ebp;
  (*regs)[X86_REG_ESP] = x86_ucontext->uc_mcontext.esp;
  (*regs)[X86_REG_EBX] = x86_ucontext->uc_mcontext.ebx;
  (*regs)[X86_REG_EDX] = x86_ucontext->uc_mcontext.edx;
  (*regs)[X86_REG_ECX] = x86_ucontext->uc_mcontext.ecx;
  (*regs)[X86_REG_EAX] = x86_ucontext->uc_mcontext.eax;
  (*regs)[X86_REG_EIP] = x86_ucontext->uc_mcontext.eip;
  regs->SetFromRaw();
  return regs;
}

static Regs* CreateFromX86_64Ucontext(void* ucontext) {
  x86_64_ucontext_t* x86_64_ucontext = reinterpret_cast<x86_64_ucontext_t*>(ucontext);

  RegsX86_64* regs = new RegsX86_64();
  // Put the registers in the expected order.

  // R8-R15
  memcpy(&(*regs)[X86_64_REG_R8], &x86_64_ucontext->uc_mcontext.r8, 8 * sizeof(uint64_t));

  // Rest of the registers.
  (*regs)[X86_64_REG_RDI] = x86_64_ucontext->uc_mcontext.rdi;
  (*regs)[X86_64_REG_RSI] = x86_64_ucontext->uc_mcontext.rsi;
  (*regs)[X86_64_REG_RBP] = x86_64_ucontext->uc_mcontext.rbp;
  (*regs)[X86_64_REG_RBX] = x86_64_ucontext->uc_mcontext.rbx;
  (*regs)[X86_64_REG_RDX] = x86_64_ucontext->uc_mcontext.rdx;
  (*regs)[X86_64_REG_RAX] = x86_64_ucontext->uc_mcontext.rax;
  (*regs)[X86_64_REG_RCX] = x86_64_ucontext->uc_mcontext.rcx;
  (*regs)[X86_64_REG_RSP] = x86_64_ucontext->uc_mcontext.rsp;
  (*regs)[X86_64_REG_RIP] = x86_64_ucontext->uc_mcontext.rip;

  regs->SetFromRaw();
  return regs;
}

Regs* Regs::CreateFromUcontext(uint32_t machine_type, void* ucontext) {
  switch (machine_type) {
    case EM_386:
      return CreateFromX86Ucontext(ucontext);
    case EM_X86_64:
      return CreateFromX86_64Ucontext(ucontext);
    case EM_ARM:
      return CreateFromArmUcontext(ucontext);
    case EM_AARCH64:
      return CreateFromArm64Ucontext(ucontext);
  }
  return nullptr;
}

uint32_t Regs::GetMachineType() {
#if defined(__arm__)
  return EM_ARM;
#elif defined(__aarch64__)
  return EM_AARCH64;
#elif defined(__i386__)
  return EM_386;
#elif defined(__x86_64__)
  return EM_X86_64;
#else
  abort();
#endif
}

Regs* Regs::CreateFromLocal() {
  Regs* regs;
#if defined(__arm__)
  regs = new RegsArm();
#elif defined(__aarch64__)
  regs = new RegsArm64();
#elif defined(__i386__)
  regs = new RegsX86();
#elif defined(__x86_64__)
  regs = new RegsX86_64();
#else
  abort();
#endif
  return regs;
}
