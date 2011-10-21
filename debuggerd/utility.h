/* system/debuggerd/utility.h
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

#ifndef _DEBUGGERD_UTILITY_H
#define _DEBUGGERD_UTILITY_H

#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <corkscrew/backtrace.h>

/* Log information onto the tombstone. */
void _LOG(int tfd, bool in_tombstone_only, const char *fmt, ...)
        __attribute__ ((format(printf, 3, 4)));

#define LOG(fmt...) _LOG(-1, 0, fmt)

/* Set to 1 for normal debug traces */
#if 0
#define XLOG(fmt...) _LOG(-1, 0, fmt)
#else
#define XLOG(fmt...) do {} while(0)
#endif

/* Set to 1 for chatty debug traces. Includes all resolved dynamic symbols */
#if 0
#define XLOG2(fmt...) _LOG(-1, 0, fmt)
#else
#define XLOG2(fmt...) do {} while(0)
#endif

/*
 * Returns true if the specified signal has an associated address.
 * (i.e. it sets siginfo_t.si_addr).
 */
bool signal_has_address(int sig);

/*
 * Dumps the backtrace and contents of the stack.
 */
void dump_backtrace_and_stack(ptrace_context_t* context, int tfd, pid_t pid, bool at_fault);

/*
 * Dumps a few bytes of memory, starting a bit before and ending a bit
 * after the specified address.
 */
void dump_memory(int tfd, pid_t tid, uintptr_t addr, bool at_fault);

/*
 * If this isn't clearly a null pointer dereference, dump the
 * /proc/maps entries near the fault address.
 *
 * This only makes sense to do on the thread that crashed.
 */
void dump_nearby_maps(ptrace_context_t* context, int tfd, pid_t tid);


#endif // _DEBUGGERD_UTILITY_H
