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

#include <stdbool.h>
#include <sys/types.h>

typedef struct {
    /* tombstone file descriptor */
    int tfd;
    /* Activity Manager socket file descriptor */
    int amfd;
    // The tid of the thread that crashed.
    pid_t crashed_tid;
    // The tid of the thread we are currently working with.
    pid_t current_tid;
} log_t;

// List of types of logs to simplify the logging decision in _LOG
enum logtype {
  ERROR,
  HEADER,
  THREAD,
  REGISTERS,
  BACKTRACE,
  MAPS,
  MEMORY,
  STACK,
  LOGS
};

/* Log information onto the tombstone. */
void _LOG(log_t* log, logtype ltype, const char *fmt, ...)
        __attribute__ ((format(printf, 3, 4)));

int wait_for_signal(pid_t tid, int* total_sleep_time_usec);
void wait_for_stop(pid_t tid, int* total_sleep_time_usec);

void dump_memory(log_t* log, pid_t tid, uintptr_t addr);

#endif // _DEBUGGERD_UTILITY_H
