/* system/debuggerd/utility.c
**
** Copyright 2008, The Android Open Source Project
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

#include <sys/ptrace.h>
#include <sys/exec_elf.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include "utility.h"

/* Get a word from pid using ptrace. The result is the return value. */
int get_remote_word(int pid, void *src)
{
    return ptrace(PTRACE_PEEKTEXT, pid, src, NULL);
}


/* Handy routine to read aggregated data from pid using ptrace. The read 
 * values are written to the dest locations directly. 
 */
void get_remote_struct(int pid, void *src, void *dst, size_t size)
{
    unsigned int i;

    for (i = 0; i+4 <= size; i+=4) {
        *(int *)(dst+i) = ptrace(PTRACE_PEEKTEXT, pid, src+i, NULL);
    }

    if (i < size) {
        int val;

        assert((size - i) < 4);
        val = ptrace(PTRACE_PEEKTEXT, pid, src+i, NULL);
        while (i < size) {
            ((unsigned char *)dst)[i] = val & 0xff;
            i++;
            val >>= 8;
        }
    }
}

/* Map a pc address to the name of the containing ELF file */
const char *map_to_name(mapinfo *mi, unsigned pc, const char* def)
{
    while(mi) {
        if((pc >= mi->start) && (pc < mi->end)){
            return mi->name;
        }
        mi = mi->next;
    }
    return def;
}

/* Find the containing map info for the pc */
const mapinfo *pc_to_mapinfo(mapinfo *mi, unsigned pc, unsigned *rel_pc)
{
    while(mi) {
        if((pc >= mi->start) && (pc < mi->end)){
            // Only calculate the relative offset for shared libraries
            if (strstr(mi->name, ".so")) {
                *rel_pc = pc - mi->start;
            }
            return mi;
        }
        mi = mi->next;
    }
    return NULL;
}
