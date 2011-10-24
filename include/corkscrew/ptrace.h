/*
 * Copyright (C) 2011 The Android Open Source Project
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

/* Useful ptrace() utility functions. */

#ifndef _CORKSCREW_PTRACE_H
#define _CORKSCREW_PTRACE_H

#include <corkscrew/map_info.h>
#include <corkscrew/symbol_table.h>

#include <sys/types.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Stores information about a process that is used for several different
 * ptrace() based operations. */
typedef struct {
    map_info_t* map_info_list;
} ptrace_context_t;

#if __i386__
/* ptrace() register context. */
typedef struct pt_regs_x86 {
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
    uint32_t esi;
    uint32_t edi;
    uint32_t ebp;
    uint32_t eax;
    uint32_t xds;
    uint32_t xes;
    uint32_t xfs;
    uint32_t xgs;
    uint32_t orig_eax;
    uint32_t eip;
    uint32_t xcs;
    uint32_t eflags;
    uint32_t esp;
    uint32_t xss;
} pt_regs_x86_t;
#endif

/*
 * Reads a word of memory safely.
 * Uses ptrace() if tid >= 0, local memory otherwise.
 * Returns false if the word could not be read.
 */
bool try_get_word(pid_t tid, uintptr_t ptr, uint32_t* out_value);

/*
 * Loads information needed for examining a remote process using ptrace().
 * The caller must already have successfully attached to the process
 * using ptrace().
 *
 * The context can be used for any threads belonging to that process
 * assuming ptrace() is attached to them before performing the actual
 * unwinding.  The context can continue to be used to decode backtraces
 * even after ptrace() has been detached from the process.
 */
ptrace_context_t* load_ptrace_context(pid_t pid);

/*
 * Frees a ptrace context.
 */
void free_ptrace_context(ptrace_context_t* context);

/*
 * Finds a symbol using ptrace.
 * Returns the containing map and information about the symbol, or
 * NULL if one or the other is not available.
 */
void find_symbol_ptrace(const ptrace_context_t* context,
        uintptr_t addr, const map_info_t** out_map_info, const symbol_t** out_symbol);

#ifdef __cplusplus
}
#endif

#endif // _CORKSCREW_PTRACE_H
