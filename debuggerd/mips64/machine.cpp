/*
 * Copyright 2014, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <sys/user.h>

#include "../utility.h"
#include "../machine.h"

#define R(x) (static_cast<unsigned long>(x))

// If configured to do so, dump memory around *all* registers
// for the crashing thread.
void dump_memory_and_code(log_t* log, pid_t tid) {
  pt_regs r;
  if (ptrace(PTRACE_GETREGS, tid, 0, &r)) {
    return;
  }

  static const char REG_NAMES[] = "$0atv0v1a0a1a2a3a4a5a6a7t0t1t2t3s0s1s2s3s4s5s6s7t8t9k0k1gpsps8ra";

  for (int reg = 0; reg < 32; reg++) {
    // skip uninteresting registers
    if (reg == 0 // $0
        || reg == 26 // $k0
        || reg == 27 // $k1
        || reg == 31 // $ra (done below)
       )
      continue;

    uintptr_t addr = R(r.regs[reg]);

    // Don't bother if it looks like a small int or ~= null, or if
    // it's in the kernel area.
    if (addr < 4096 || addr >= 0x4000000000000000) {
      continue;
    }

    _LOG(log, logtype::MEMORY, "\nmemory near %.2s:\n", &REG_NAMES[reg * 2]);
    dump_memory(log, tid, addr);
  }

  unsigned long pc = R(r.cp0_epc);
  unsigned long ra = R(r.regs[31]);

  _LOG(log, logtype::MEMORY, "\ncode around pc:\n");
  dump_memory(log, tid, (uintptr_t)pc);

  if (pc != ra) {
    _LOG(log, logtype::MEMORY, "\ncode around ra:\n");
    dump_memory(log, tid, (uintptr_t)ra);
  }
}

void dump_registers(log_t* log, pid_t tid) {
  pt_regs r;
  if(ptrace(PTRACE_GETREGS, tid, 0, &r)) {
    _LOG(log, logtype::ERROR, "cannot get registers: %s\n", strerror(errno));
    return;
  }

  _LOG(log, logtype::REGISTERS, " zr %016lx  at %016lx  v0 %016lx  v1 %016lx\n",
       R(r.regs[0]), R(r.regs[1]), R(r.regs[2]), R(r.regs[3]));
  _LOG(log, logtype::REGISTERS, " a0 %016lx  a1 %016lx  a2 %016lx  a3 %016lx\n",
       R(r.regs[4]), R(r.regs[5]), R(r.regs[6]), R(r.regs[7]));
  _LOG(log, logtype::REGISTERS, " a4 %016lx  a5 %016lx  a6 %016lx  a7 %016lx\n",
       R(r.regs[8]), R(r.regs[9]), R(r.regs[10]), R(r.regs[11]));
  _LOG(log, logtype::REGISTERS, " t0 %016lx  t1 %016lx  t2 %016lx  t3 %016lx\n",
       R(r.regs[12]), R(r.regs[13]), R(r.regs[14]), R(r.regs[15]));
  _LOG(log, logtype::REGISTERS, " s0 %016lx  s1 %016lx  s2 %016lx  s3 %016lx\n",
       R(r.regs[16]), R(r.regs[17]), R(r.regs[18]), R(r.regs[19]));
  _LOG(log, logtype::REGISTERS, " s4 %016lx  s5 %016lx  s6 %016lx  s7 %016lx\n",
       R(r.regs[20]), R(r.regs[21]), R(r.regs[22]), R(r.regs[23]));
  _LOG(log, logtype::REGISTERS, " t8 %016lx  t9 %016lx  k0 %016lx  k1 %016lx\n",
       R(r.regs[24]), R(r.regs[25]), R(r.regs[26]), R(r.regs[27]));
  _LOG(log, logtype::REGISTERS, " gp %016lx  sp %016lx  s8 %016lx  ra %016lx\n",
       R(r.regs[28]), R(r.regs[29]), R(r.regs[30]), R(r.regs[31]));
  _LOG(log, logtype::REGISTERS, " hi %016lx  lo %016lx bva %016lx epc %016lx\n",
       R(r.hi), R(r.lo), R(r.cp0_badvaddr), R(r.cp0_epc));
}
