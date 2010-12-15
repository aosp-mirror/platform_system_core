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

#include <stdio.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <dirent.h>

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/exec_elf.h>
#include <sys/stat.h>

#include <cutils/sockets.h>
#include <cutils/properties.h>

#include <linux/input.h>

#include "utility.h"

#ifdef WITH_VFP
#ifdef WITH_VFP_D32
#define NUM_VFP_REGS 32
#else
#define NUM_VFP_REGS 16
#endif
#endif

/* Main entry point to get the backtrace from the crashing process */
extern int unwind_backtrace_with_ptrace(int tfd, pid_t pid, mapinfo *map,
                                        unsigned int sp_list[],
                                        int *frame0_pc_sane,
                                        bool at_fault);

void dump_stack_and_code(int tfd, int pid, mapinfo *map,
                         int unwind_depth, unsigned int sp_list[],
                         bool at_fault)
{
    unsigned int sp, pc, p, end, data;
    struct pt_regs r;
    int sp_depth;
    bool only_in_tombstone = !at_fault;
    char code_buffer[80];

    if(ptrace(PTRACE_GETREGS, pid, 0, &r)) return;
    sp = r.ARM_sp;
    pc = r.ARM_pc;

    _LOG(tfd, only_in_tombstone, "\ncode around pc:\n");

    end = p = pc & ~3;
    p -= 32;
    if (p > end)
        p = 0;
    end += 32;
    if (end < p)
        end = ~0;

    /* Dump the code around PC as:
     *  addr       contents
     *  00008d34   fffffcd0 4c0eb530 b0934a0e 1c05447c
     *  00008d44   f7ff18a0 490ced94 68035860 d0012b00
     */
    while (p <= end) {
        int i;

        sprintf(code_buffer, "%08x ", p);
        for (i = 0; i < 4; i++) {
            data = ptrace(PTRACE_PEEKTEXT, pid, (void*)p, NULL);
            sprintf(code_buffer + strlen(code_buffer), "%08x ", data);
            p += 4;
        }
        _LOG(tfd, only_in_tombstone, "%s\n", code_buffer);
    }

    if ((unsigned) r.ARM_lr != pc) {
        _LOG(tfd, only_in_tombstone, "\ncode around lr:\n");

        end = p = r.ARM_lr & ~3;
        p -= 32;
        if (p > end)
            p = 0;
        end += 32;
        if (end < p)
            end = ~0;

        /* Dump the code around LR as:
         *  addr       contents
         *  00008d34   fffffcd0 4c0eb530 b0934a0e 1c05447c
         *  00008d44   f7ff18a0 490ced94 68035860 d0012b00
         */
        while (p <= end) {
            int i;

            sprintf(code_buffer, "%08x ", p);
            for (i = 0; i < 4; i++) {
                data = ptrace(PTRACE_PEEKTEXT, pid, (void*)p, NULL);
                sprintf(code_buffer + strlen(code_buffer), "%08x ", data);
                p += 4;
            }
            _LOG(tfd, only_in_tombstone, "%s\n", code_buffer);
        }
    }

    p = sp - 64;
    if (p > sp)
        p = 0;
    p &= ~3;
    if (unwind_depth != 0) {
        if (unwind_depth < STACK_CONTENT_DEPTH) {
            end = sp_list[unwind_depth-1];
        }
        else {
            end = sp_list[STACK_CONTENT_DEPTH-1];
        }
    }
    else {
        end = sp | 0x000000ff;
        end += 0xff;
        if (end < sp)
            end = ~0;
    }

    _LOG(tfd, only_in_tombstone, "\nstack:\n");

    /* If the crash is due to PC == 0, there will be two frames that
     * have identical SP value.
     */
    if (sp_list[0] == sp_list[1]) {
        sp_depth = 1;
    }
    else {
        sp_depth = 0;
    }

    while (p <= end) {
         char *prompt;
         char level[16];
         data = ptrace(PTRACE_PEEKTEXT, pid, (void*)p, NULL);
         if (p == sp_list[sp_depth]) {
             sprintf(level, "#%02d", sp_depth++);
             prompt = level;
         }
         else {
             prompt = "   ";
         }

         /* Print the stack content in the log for the first 3 frames. For the
          * rest only print them in the tombstone file.
          */
         _LOG(tfd, (sp_depth > 2) || only_in_tombstone,
              "%s %08x  %08x  %s\n", prompt, p, data,
              map_to_name(map, data, ""));
         p += 4;
    }
    /* print another 64-byte of stack data after the last frame */

    end = p+64;
    if (end < p)
        end = ~0;

    while (p <= end) {
         data = ptrace(PTRACE_PEEKTEXT, pid, (void*)p, NULL);
         _LOG(tfd, (sp_depth > 2) || only_in_tombstone,
              "    %08x  %08x  %s\n", p, data,
              map_to_name(map, data, ""));
         p += 4;
    }
}

void dump_pc_and_lr(int tfd, int pid, mapinfo *map, int unwound_level,
                    bool at_fault)
{
    struct pt_regs r;

    if(ptrace(PTRACE_GETREGS, pid, 0, &r)) {
        _LOG(tfd, !at_fault, "tid %d not responding!\n", pid);
        return;
    }

    if (unwound_level == 0) {
        _LOG(tfd, !at_fault, "         #%02d  pc %08x  %s\n", 0, r.ARM_pc,
             map_to_name(map, r.ARM_pc, "<unknown>"));
    }
    _LOG(tfd, !at_fault, "         #%02d  lr %08x  %s\n", 1, r.ARM_lr,
            map_to_name(map, r.ARM_lr, "<unknown>"));
}

void dump_registers(int tfd, int pid, bool at_fault)
{
    struct pt_regs r;
    bool only_in_tombstone = !at_fault;

    if(ptrace(PTRACE_GETREGS, pid, 0, &r)) {
        _LOG(tfd, only_in_tombstone,
             "cannot get registers: %s\n", strerror(errno));
        return;
    }

    _LOG(tfd, only_in_tombstone, " r0 %08x  r1 %08x  r2 %08x  r3 %08x\n",
         r.ARM_r0, r.ARM_r1, r.ARM_r2, r.ARM_r3);
    _LOG(tfd, only_in_tombstone, " r4 %08x  r5 %08x  r6 %08x  r7 %08x\n",
         r.ARM_r4, r.ARM_r5, r.ARM_r6, r.ARM_r7);
    _LOG(tfd, only_in_tombstone, " r8 %08x  r9 %08x  10 %08x  fp %08x\n",
         r.ARM_r8, r.ARM_r9, r.ARM_r10, r.ARM_fp);
    _LOG(tfd, only_in_tombstone,
         " ip %08x  sp %08x  lr %08x  pc %08x  cpsr %08x\n",
         r.ARM_ip, r.ARM_sp, r.ARM_lr, r.ARM_pc, r.ARM_cpsr);

#ifdef WITH_VFP
    struct user_vfp vfp_regs;
    int i;

    if(ptrace(PTRACE_GETVFPREGS, pid, 0, &vfp_regs)) {
        _LOG(tfd, only_in_tombstone,
             "cannot get registers: %s\n", strerror(errno));
        return;
    }

    for (i = 0; i < NUM_VFP_REGS; i += 2) {
        _LOG(tfd, only_in_tombstone,
             " d%-2d %016llx  d%-2d %016llx\n",
              i, vfp_regs.fpregs[i], i+1, vfp_regs.fpregs[i+1]);
    }
    _LOG(tfd, only_in_tombstone, " scr %08lx\n\n", vfp_regs.fpscr);
#endif
}
