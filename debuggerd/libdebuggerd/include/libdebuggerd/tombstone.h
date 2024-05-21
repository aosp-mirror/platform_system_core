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

#ifndef _DEBUGGERD_TOMBSTONE_H
#define _DEBUGGERD_TOMBSTONE_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>

#include <functional>
#include <map>
#include <string>

#include <android-base/unique_fd.h>

#include "open_files_list.h"
#include "tombstone.pb.h"
#include "types.h"

// Forward declarations
class BacktraceFrame;
class Cause;
class Tombstone;

namespace unwindstack {
struct FrameData;
class AndroidUnwinder;
}

// The maximum number of frames to save when unwinding.
constexpr size_t kMaxFrames = 256;

/* Create and open a tombstone file for writing.
 * Returns a writable file descriptor, or -1 with errno set appropriately.
 * If out_path is non-null, *out_path is set to the path of the tombstone file.
 */
int open_tombstone(std::string* path);

/* Creates a tombstone file and writes the crash dump to it. */
void engrave_tombstone(android::base::unique_fd output_fd, android::base::unique_fd proto_fd,
                       unwindstack::AndroidUnwinder* unwinder,
                       const std::map<pid_t, ThreadInfo>& thread_info, pid_t target_thread,
                       const ProcessInfo& process_info, OpenFilesList* open_files,
                       std::string* amfd_data, const Architecture* guest_arch = nullptr,
                       unwindstack::AndroidUnwinder* guest_unwinder = nullptr);

void engrave_tombstone_ucontext(int tombstone_fd, int proto_fd, uint64_t abort_msg_address,
                                siginfo_t* siginfo, ucontext_t* ucontext);

void engrave_tombstone_proto(Tombstone* tombstone, unwindstack::AndroidUnwinder* unwinder,
                             const std::map<pid_t, ThreadInfo>& threads, pid_t target_thread,
                             const ProcessInfo& process_info, const OpenFilesList* open_files,
                             const Architecture* guest_arch,
                             unwindstack::AndroidUnwinder* guest_unwinder);

bool tombstone_proto_to_text(
    const Tombstone& tombstone,
    std::function<void(const std::string& line, bool should_log)> callback);

void fill_in_backtrace_frame(BacktraceFrame* f, const unwindstack::FrameData& frame);
void set_human_readable_cause(Cause* cause, uint64_t fault_addr);

#endif  // _DEBUGGERD_TOMBSTONE_H
