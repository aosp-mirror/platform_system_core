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

#ifndef _DEBUGGERD_BACKTRACE_H
#define _DEBUGGERD_BACKTRACE_H

#include <sys/types.h>
#include <sys/ucontext.h>

#include <map>
#include <string>

#include <android-base/unique_fd.h>

#include "types.h"
#include "utility.h"

// Forward delcaration
namespace unwindstack {
class AndroidUnwinder;
}

// Dumps a backtrace using a format similar to what Dalvik uses so that the result
// can be intermixed in a bug report.
void dump_backtrace(android::base::unique_fd output_fd, unwindstack::AndroidUnwinder* unwinder,
                    const std::map<pid_t, ThreadInfo>& thread_info, pid_t target_thread);

void dump_backtrace_header(int output_fd);
void dump_backtrace_thread(int output_fd, unwindstack::AndroidUnwinder* unwinder,
                           const ThreadInfo& thread);
void dump_backtrace_footer(int output_fd);

#endif // _DEBUGGERD_BACKTRACE_H
