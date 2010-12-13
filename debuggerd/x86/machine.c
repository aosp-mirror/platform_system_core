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

#include "../utility.h"
#include "x86_utility.h"

void dump_registers(int tfd, int pid, bool at_fault)
{
    struct pt_regs_x86 r;
    bool only_in_tombstone = !at_fault;

    if(ptrace(PTRACE_GETREGS, pid, 0, &r)) {
        _LOG(tfd, only_in_tombstone,
             "cannot get registers: %s\n", strerror(errno));
        return;
    }
//if there is no stack, no print just like arm
    if(!r.ebp)
        return;
    _LOG(tfd, only_in_tombstone, " eax %08x  ebx %08x  ecx %08x  edx %08x\n",
         r.eax, r.ebx, r.ecx, r.edx);
    _LOG(tfd, only_in_tombstone, " esi %08x  edi %08x\n",
         r.esi, r.edi);
    _LOG(tfd, only_in_tombstone, " xcs %08x  xds %08x  xes %08x  xfs %08x xss %08x\n",
         r.xcs, r.xds, r.xes, r.xfs, r.xss);
    _LOG(tfd, only_in_tombstone,
         " eip %08x  ebp %08x  esp %08x  flags %08x\n",
         r.eip, r.ebp, r.esp, r.eflags);
}
