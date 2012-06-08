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
    /* if true, does not log anything to the Android logcat */
    bool quiet;
} log_t;

/* Log information onto the tombstone. */
void _LOG(log_t* log, bool in_tombstone_only, const char *fmt, ...)
        __attribute__ ((format(printf, 3, 4)));

#define LOG(fmt...) _LOG(NULL, 0, fmt)

/* Set to 1 for normal debug traces */
#if 0
#define XLOG(fmt...) _LOG(NULL, 0, fmt)
#else
#define XLOG(fmt...) do {} while(0)
#endif

/* Set to 1 for chatty debug traces. Includes all resolved dynamic symbols */
#if 0
#define XLOG2(fmt...) _LOG(NULL, 0, fmt)
#else
#define XLOG2(fmt...) do {} while(0)
#endif

int wait_for_signal(pid_t tid, int* total_sleep_time_usec);
void wait_for_stop(pid_t tid, int* total_sleep_time_usec);

#endif // _DEBUGGERD_UTILITY_H
