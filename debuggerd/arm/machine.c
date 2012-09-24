/* system/debuggerd/debuggerd.c
**
** Copyright 2006, The Android Open Source Project
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

#ifdef WITH_VFP
#ifdef WITH_VFP_D32
#define NUM_VFP_REGS 32
#else
#define NUM_VFP_REGS 16
#endif
#endif

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
    /* Dump more memory content for the crashing thread. */
    end = p + 256;
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

            /* Enable the following code blob to dump ASCII values */
#if 0
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
#endif
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
    struct pt_regs regs;
    if(ptrace(PTRACE_GETREGS, tid, 0, &regs)) {
        return;
    }

    if (at_fault && DUMP_MEMORY_FOR_ALL_REGISTERS) {
        static const char REG_NAMES[] = "r0r1r2r3r4r5r6r7r8r9slfpipsp";

        for (int reg = 0; reg < 14; reg++) {
            /* this may not be a valid way to access, but it'll do for now */
            uintptr_t addr = regs.uregs[reg];

            /*
             * Don't bother if it looks like a small int or ~= null, or if
             * it's in the kernel area.
             */
            if (addr < 4096 || addr >= 0xc0000000) {
                continue;
            }

            _LOG(log, false, "\nmemory near %.2s:\n", &REG_NAMES[reg * 2]);
            dump_memory(log, tid, addr, at_fault);
        }
    }

    _LOG(log, !at_fault, "\ncode around pc:\n");
    dump_memory(log, tid, (uintptr_t)regs.ARM_pc, at_fault);

    if (regs.ARM_pc != regs.ARM_lr) {
        _LOG(log, !at_fault, "\ncode around lr:\n");
        dump_memory(log, tid, (uintptr_t)regs.ARM_lr, at_fault);
    }
}

void dump_registers(const ptrace_context_t* context __attribute((unused)),
        log_t* log, pid_t tid, bool at_fault)
{
    struct pt_regs r;
    bool only_in_tombstone = !at_fault;

    if(ptrace(PTRACE_GETREGS, tid, 0, &r)) {
        _LOG(log, only_in_tombstone, "cannot get registers: %s\n", strerror(errno));
        return;
    }

    _LOG(log, only_in_tombstone, "    r0 %08x  r1 %08x  r2 %08x  r3 %08x\n",
            (uint32_t)r.ARM_r0, (uint32_t)r.ARM_r1, (uint32_t)r.ARM_r2, (uint32_t)r.ARM_r3);
    _LOG(log, only_in_tombstone, "    r4 %08x  r5 %08x  r6 %08x  r7 %08x\n",
            (uint32_t)r.ARM_r4, (uint32_t)r.ARM_r5, (uint32_t)r.ARM_r6, (uint32_t)r.ARM_r7);
    _LOG(log, only_in_tombstone, "    r8 %08x  r9 %08x  sl %08x  fp %08x\n",
            (uint32_t)r.ARM_r8, (uint32_t)r.ARM_r9, (uint32_t)r.ARM_r10, (uint32_t)r.ARM_fp);
    _LOG(log, only_in_tombstone, "    ip %08x  sp %08x  lr %08x  pc %08x  cpsr %08x\n",
            (uint32_t)r.ARM_ip, (uint32_t)r.ARM_sp, (uint32_t)r.ARM_lr,
            (uint32_t)r.ARM_pc, (uint32_t)r.ARM_cpsr);

#ifdef WITH_VFP
    struct user_vfp vfp_regs;
    int i;

    if(ptrace(PTRACE_GETVFPREGS, tid, 0, &vfp_regs)) {
        _LOG(log, only_in_tombstone, "cannot get registers: %s\n", strerror(errno));
        return;
    }

    for (i = 0; i < NUM_VFP_REGS; i += 2) {
        _LOG(log, only_in_tombstone, "    d%-2d %016llx  d%-2d %016llx\n",
                i, vfp_regs.fpregs[i], i+1, vfp_regs.fpregs[i+1]);
    }
    _LOG(log, only_in_tombstone, "    scr %08lx\n", vfp_regs.fpscr);
#endif
}
