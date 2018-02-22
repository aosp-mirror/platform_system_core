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

#include <stdint.h>

#include <functional>

#include <unwindstack/Elf.h>
#include <unwindstack/MachineArm.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Memory.h>
#include <unwindstack/RegsArm.h>
#include <unwindstack/UcontextArm.h>
#include <unwindstack/UserArm.h>

namespace unwindstack {

RegsArm::RegsArm()
    : RegsImpl<uint32_t>(ARM_REG_LAST, ARM_REG_SP, Location(LOCATION_REGISTER, ARM_REG_LR)) {}

ArchEnum RegsArm::Arch() {
  return ARCH_ARM;
}

uint64_t RegsArm::GetPcAdjustment(uint64_t rel_pc, Elf* elf) {
  uint64_t load_bias = elf->GetLoadBias();
  if (rel_pc < load_bias) {
    return 0;
  }
  uint64_t adjusted_rel_pc = rel_pc - load_bias;
  if (adjusted_rel_pc < 5) {
    return 0;
  }

  if (adjusted_rel_pc & 1) {
    // This is a thumb instruction, it could be 2 or 4 bytes.
    uint32_t value;
    if (!elf->memory()->ReadFully(adjusted_rel_pc - 5, &value, sizeof(value)) ||
        (value & 0xe000f000) != 0xe000f000) {
      return 2;
    }
  }
  return 4;
}

void RegsArm::SetFromRaw() {
  set_pc(regs_[ARM_REG_PC]);
  set_sp(regs_[ARM_REG_SP]);
}

bool RegsArm::SetPcFromReturnAddress(Memory*) {
  if (pc() == regs_[ARM_REG_LR]) {
    return false;
  }

  set_pc(regs_[ARM_REG_LR]);
  return true;
}

void RegsArm::IterateRegisters(std::function<void(const char*, uint64_t)> fn) {
  fn("r0", regs_[ARM_REG_R0]);
  fn("r1", regs_[ARM_REG_R1]);
  fn("r2", regs_[ARM_REG_R2]);
  fn("r3", regs_[ARM_REG_R3]);
  fn("r4", regs_[ARM_REG_R4]);
  fn("r5", regs_[ARM_REG_R5]);
  fn("r6", regs_[ARM_REG_R6]);
  fn("r7", regs_[ARM_REG_R7]);
  fn("r8", regs_[ARM_REG_R8]);
  fn("r9", regs_[ARM_REG_R9]);
  fn("r10", regs_[ARM_REG_R10]);
  fn("r11", regs_[ARM_REG_R11]);
  fn("ip", regs_[ARM_REG_R12]);
  fn("sp", regs_[ARM_REG_SP]);
  fn("lr", regs_[ARM_REG_LR]);
  fn("pc", regs_[ARM_REG_PC]);
}

Regs* RegsArm::Read(void* remote_data) {
  arm_user_regs* user = reinterpret_cast<arm_user_regs*>(remote_data);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &user->regs[0], ARM_REG_LAST * sizeof(uint32_t));
  regs->SetFromRaw();
  return regs;
}

Regs* RegsArm::CreateFromUcontext(void* ucontext) {
  arm_ucontext_t* arm_ucontext = reinterpret_cast<arm_ucontext_t*>(ucontext);

  RegsArm* regs = new RegsArm();
  memcpy(regs->RawData(), &arm_ucontext->uc_mcontext.regs[0], ARM_REG_LAST * sizeof(uint32_t));
  regs->SetFromRaw();
  return regs;
}

bool RegsArm::StepIfSignalHandler(uint64_t rel_pc, Elf* elf, Memory* process_memory) {
  uint32_t data;
  Memory* elf_memory = elf->memory();
  // Read from elf memory since it is usually more expensive to read from
  // process memory.
  if (!elf_memory->ReadFully(rel_pc, &data, sizeof(data))) {
    return false;
  }

  uint64_t offset = 0;
  if (data == 0xe3a07077 || data == 0xef900077 || data == 0xdf002777) {
    // non-RT sigreturn call.
    // __restore:
    //
    // Form 1 (arm):
    // 0x77 0x70              mov r7, #0x77
    // 0xa0 0xe3              svc 0x00000000
    //
    // Form 2 (arm):
    // 0x77 0x00 0x90 0xef    svc 0x00900077
    //
    // Form 3 (thumb):
    // 0x77 0x27              movs r7, #77
    // 0x00 0xdf              svc 0
    if (!process_memory->ReadFully(sp(), &data, sizeof(data))) {
      return false;
    }
    if (data == 0x5ac3c35a) {
      // SP + uc_mcontext offset + r0 offset.
      offset = sp() + 0x14 + 0xc;
    } else {
      // SP + r0 offset
      offset = sp() + 0xc;
    }
  } else if (data == 0xe3a070ad || data == 0xef9000ad || data == 0xdf0027ad) {
    // RT sigreturn call.
    // __restore_rt:
    //
    // Form 1 (arm):
    // 0xad 0x70      mov r7, #0xad
    // 0xa0 0xe3      svc 0x00000000
    //
    // Form 2 (arm):
    // 0xad 0x00 0x90 0xef    svc 0x009000ad
    //
    // Form 3 (thumb):
    // 0xad 0x27              movs r7, #ad
    // 0x00 0xdf              svc 0
    if (!process_memory->ReadFully(sp(), &data, sizeof(data))) {
      return false;
    }
    if (data == sp() + 8) {
      // SP + 8 + sizeof(siginfo_t) + uc_mcontext_offset + r0 offset
      offset = sp() + 8 + 0x80 + 0x14 + 0xc;
    } else {
      // SP + sizeof(siginfo_t) + uc_mcontext_offset + r0 offset
      offset = sp() + 0x80 + 0x14 + 0xc;
    }
  }
  if (offset == 0) {
    return false;
  }

  if (!process_memory->ReadFully(offset, regs_.data(), sizeof(uint32_t) * ARM_REG_LAST)) {
    return false;
  }
  SetFromRaw();
  return true;
}

}  // namespace unwindstack
