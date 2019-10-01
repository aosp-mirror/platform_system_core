/* system/core/include/logwrap/logwrap.h
 *
 * Copyright 2013, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

/*
 * Run a command while logging its stdout and stderr
 *
 * Arguments:
 *   argc:   the number of elements in argv
 *   argv:   an array of strings containing the command to be executed and its
 *           arguments as separate strings. argv does not need to be
 *           NULL-terminated
 *   status: the equivalent child status as populated by wait(status). This
 *           value is only valid when logwrap successfully completes. If NULL
 *           the return value of the child will be the function's return value.
 *   forward_signals: set to true if you want to forward SIGINT, SIGQUIT, and
 *           SIGHUP to the child process, while it is running.  You likely do
 *           not need to use this; it is primarily for the logwrapper
 *           executable itself.
 *   log_target: Specify where to log the output of the child, either LOG_NONE,
 *           LOG_ALOG (for the Android system log), LOG_KLOG (for the kernel
 *           log), or LOG_FILE (and you need to specify a pathname in the
 *           file_path argument, otherwise pass NULL).  These are bit fields,
 *           and can be OR'ed together to log to multiple places.
 *   abbreviated: If true, capture up to the first 100 lines and last 4K of
 *           output from the child.  The abbreviated output is not dumped to
 *           the specified log until the child has exited.
 *   file_path: if log_target has the LOG_FILE bit set, then this parameter
 *           must be set to the pathname of the file to log to.
 *
 * Return value:
 *   0 when logwrap successfully run the child process and captured its status
 *   -1 when an internal error occurred
 *   -ECHILD if status is NULL and the child didn't exit properly
 *   the return value of the child if it exited properly and status is NULL
 *
 */

/* Values for the log_target parameter logwrap_fork_execvp() */
#define LOG_NONE        0
#define LOG_ALOG        1
#define LOG_KLOG        2
#define LOG_FILE        4

int logwrap_fork_execvp(int argc, const char* const* argv, int* status, bool forward_signals,
                        int log_target, bool abbreviated, const char* file_path);
