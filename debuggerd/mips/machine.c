/* system/debuggerd/debuggerd.c
**
** Copyright 2012, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License");
** you may not use this file except in compliance with the License.
** You may obtain a copy of the License at
**
**     http://www.apache.org/licenses/LICENSE-2.0
**
** Unless required by applicable law or agreed to in writing, software
** distributed under the License is distributed on an "AS IS" BASIS,
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
** See the License for the specific language governing permissions and
** limitations under the License.
*/

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <corkscrew/ptrace.h>

#include <linux/user.h>

#include "../utility.h"
#include "../machine.h"

/* enable to dump memory pointed to by every register */
#define DUMP_MEMORY_FOR_ALL_REGISTERS 1

#define R(x) ((unsigned int)(x))

static void dump_memory(log_t* log, pid_t tid, uintptr_t addr, bool at_fault) {
    char code_buffer[64];       /* actual 8+1+((8+1)*4) + 1 == 45 */
    char ascii_buffer[32];      /* actual 16 + 1 == 17 */
    uintptr_t p, end;

    p = addr & ~3;
    p -= 32;
    if (p > addr) {
        /* catch underflow */
        p = 0;
    }
    end = p + 80;
    /* catch overflow; 'end - p' has to be multiples of 16 */
    while (end < p)
        end -= 16;

    /* Dump the code around PC as:
     *  addr     contents                             ascii
     *  00008d34 ef000000 e8bd0090 e1b00000 512fff1e  ............../Q
     *  00008d44 ea00b1f9 e92d0090 e3a070fc ef000000  ......-..p......
     */
    while (p < end) {
        char* asc_out = ascii_buffer;

        sprintf(code_buffer, "%08x ", p);

        int i;
        for (i = 0; i < 4; i++) {
            /*
             * If we see (data == -1 && errno != 0), we know that the ptrace
             * call failed, probably because we're dumping memory in an
             * unmapped or inaccessible page.  I don't know if there's
             * value in making that explicit in the output -- it likely
             * just complicates parsing and clarifies nothing for the
             * enlightened reader.
             */
            long data = ptrace(PTRACE_PEEKTEXT, tid, (void*)p, NULL);
            sprintf(code_buffer + strlen(code_buffer), "%08lx ", data);

            int j;
            for (j = 0; j < 4; j++) {
                /*
                 * Our isprint() allows high-ASCII characters that display
                 * differently (often badly) in different viewers, so we
                 * just use a simpler test.
                 */
                char val = (data >> (j*8)) & 0xff;
                if (val >= 0x20 && val < 0x7f) {
                    *asc_out++ = val;
                } else {
                    *asc_out++ = '.';
                }
            }
            p += 4;
        }
        *asc_out = '\0';
        _LOG(log, !at_fault, "    %s %s\n", code_buffer, ascii_buffer);
    }
}

/*
 * If configured to do so, dump memory around *all* registers
 * for the crashing thread.
 */
void dump_memory_and_code(const ptrace_context_t* context __attribute((unused)),
        log_t* log, pid_t tid, bool at_fault) {
    pt_regs_mips_t r;
    if(ptrace(PTRACE_GETREGS, tid, 0, &r)) {
        return;
    }

    if (at_fault && DUMP_MEMORY_FOR_ALL_REGISTERS) {
        static const char REG_NAMES[] = "$0atv0v1a0a1a2a3t0t1t2t3t4t5t6t7s0s1s2s3s4s5s6s7t8t9k0k1gpsps8ra";

        for (int reg = 0; reg < 32; reg++) {
            /* skip uninteresting registers */
            if (reg == 0 /* $0 */
                || reg == 26 /* $k0 */
                || reg == 27 /* $k1 */
                || reg == 31 /* $ra (done below) */
               )
               continue;

            uintptr_t addr = R(r.regs[reg]);

            /*
             * Don't bother if it looks like a small int or ~= null, or if
             * it's in the kernel area.
             */
            if (addr < 4096 || addr >= 0x80000000) {
                continue;
            }

            _LOG(log, false, "\nmemory near %.2s:\n", &REG_NAMES[reg * 2]);
            dump_memory(log, tid, addr, at_fault);
        }
    }

    unsigned int pc = R(r.cp0_epc);
    unsigned int ra = R(r.regs[31]);

    _LOG(log, !at_fault, "\ncode around pc:\n");
    dump_memory(log, tid, (uintptr_t)pc, at_fault);

    if (pc != ra) {
        _LOG(log, !at_fault, "\ncode around ra:\n");
        dump_memory(log, tid, (uintptr_t)ra, at_fault);
    }
}

void dump_registers(const ptrace_context_t* context __attribute((unused)),
        log_t* log, pid_t tid, bool at_fault)
{
    pt_regs_mips_t r;
    bool only_in_tombstone = !at_fault;

    if(ptrace(PTRACE_GETREGS, tid, 0, &r)) {
        _LOG(log, only_in_tombstone, "cannot get registers: %s\n", strerror(errno));
        return;
    }

    _LOG(log, only_in_tombstone, " zr %08x  at %08x  v0 %08x  v1 %08x\n",
     R(r.regs[0]), R(r.regs[1]), R(r.regs[2]), R(r.regs[3]));
    _LOG(log, only_in_tombstone, " a0 %08x  a1 %08x  a2 %08x  a3 %08x\n",
     R(r.regs[4]), R(r.regs[5]), R(r.regs[6]), R(r.regs[7]));
    _LOG(log, only_in_tombstone, " t0 %08x  t1 %08x  t2 %08x  t3 %08x\n",
     R(r.regs[8]), R(r.regs[9]), R(r.regs[10]), R(r.regs[11]));
    _LOG(log, only_in_tombstone, " t4 %08x  t5 %08x  t6 %08x  t7 %08x\n",
     R(r.regs[12]), R(r.regs[13]), R(r.regs[14]), R(r.regs[15]));
    _LOG(log, only_in_tombstone, " s0 %08x  s1 %08x  s2 %08x  s3 %08x\n",
     R(r.regs[16]), R(r.regs[17]), R(r.regs[18]), R(r.regs[19]));
    _LOG(log, only_in_tombstone, " s4 %08x  s5 %08x  s6 %08x  s7 %08x\n",
     R(r.regs[20]), R(r.regs[21]), R(r.regs[22]), R(r.regs[23]));
    _LOG(log, only_in_tombstone, " t8 %08x  t9 %08x  k0 %08x  k1 %08x\n",
     R(r.regs[24]), R(r.regs[25]), R(r.regs[26]), R(r.regs[27]));
    _LOG(log, only_in_tombstone, " gp %08x  sp %08x  s8 %08x  ra %08x\n",
     R(r.regs[28]), R(r.regs[29]), R(r.regs[30]), R(r.regs[31]));
    _LOG(log, only_in_tombstone, " hi %08x  lo %08x bva %08x epc %08x\n",
     R(r.hi), R(r.lo), R(r.cp0_badvaddr), R(r.cp0_epc));
}
