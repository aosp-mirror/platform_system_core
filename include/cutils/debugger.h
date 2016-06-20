/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef __CUTILS_DEBUGGER_H
#define __CUTILS_DEBUGGER_H

#include <sys/cdefs.h>
#include <sys/types.h>

#include "debuggerd/client.h"

__BEGIN_DECLS

/* Dumps a process backtrace, registers, and stack to a tombstone file (requires root).
 * Stores the tombstone path in the provided buffer.
 * Returns 0 on success, -1 on error.
 */
int dump_tombstone(pid_t tid, char* pathbuf, size_t pathlen);

/* Dumps a process backtrace, registers, and stack to a tombstone file (requires root).
 * Stores the tombstone path in the provided buffer.
 * If reading debugger data from debuggerd ever takes longer than timeout_secs
 * seconds, then stop and return an error.
 * Returns 0 on success, -1 on error.
 */
int dump_tombstone_timeout(pid_t tid, char* pathbuf, size_t pathlen, int timeout_secs);

/* Dumps a process backtrace only to the specified file (requires root).
 * Returns 0 on success, -1 on error.
 */
int dump_backtrace_to_file(pid_t tid, int fd);

/* Dumps a process backtrace only to the specified file (requires root).
 * If reading debugger data from debuggerd ever takes longer than timeout_secs
 * seconds, then stop and return an error.
 * Returns 0 on success, -1 on error.
 */
int dump_backtrace_to_file_timeout(pid_t tid, int fd, int timeout_secs);

__END_DECLS

#endif /* __CUTILS_DEBUGGER_H */
