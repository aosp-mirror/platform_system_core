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

typedef struct {
    /* tombstone file descriptor */
    int tfd;
    /* Activity Manager socket file descriptor */
    int amfd;
    /* if true, does not log anything to the Android logcat or Activity Manager */
    bool quiet;
} log_t;

/* Log information onto the tombstone.  scopeFlags is a bitmask of the flags defined
 * here. */
void _LOG(log_t* log, int scopeFlags, const char *fmt, ...)
        __attribute__ ((format(printf, 3, 4)));

/* The message pertains specifically to the faulting thread / process */
#define SCOPE_AT_FAULT (1 << 0)
/* The message contains sensitive information such as RAM contents */
#define SCOPE_SENSITIVE  (1 << 1)

#define IS_AT_FAULT(x)    (((x) & SCOPE_AT_FAULT) != 0)
#define IS_SENSITIVE(x)    (((x) & SCOPE_SENSITIVE) != 0)

/* Further helpful macros */
#define LOG(fmt...) _LOG(NULL, SCOPE_AT_FAULT, fmt)

/* Set to 1 for normal debug traces */
#if 0
#define XLOG(fmt...) _LOG(NULL, SCOPE_AT_FAULT, fmt)
#else
#define XLOG(fmt...) do {} while(0)
#endif

/* Set to 1 for chatty debug traces. Includes all resolved dynamic symbols */
#if 0
#define XLOG2(fmt...) _LOG(NULL, SCOPE_AT_FAULT, fmt)
#else
#define XLOG2(fmt...) do {} while(0)
#endif

int wait_for_signal(pid_t tid, int* total_sleep_time_usec);
void wait_for_stop(pid_t tid, int* total_sleep_time_usec);

bool pid_contains_tid(pid_t pid, pid_t tid);

// Attach to a thread, and verify that it's still a member of the given process
bool ptrace_attach_thread(pid_t pid, pid_t tid);

#endif // _DEBUGGERD_UTILITY_H
