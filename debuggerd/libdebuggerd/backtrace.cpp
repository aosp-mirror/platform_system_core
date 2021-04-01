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

#define LOG_TAG "DEBUG"

#include "libdebuggerd/backtrace.h"

#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <unistd.h>

#include <map>
#include <memory>
#include <string>

#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <log/log.h>
#include <unwindstack/Unwinder.h>

#include "libdebuggerd/types.h"
#include "libdebuggerd/utility.h"
#include "util.h"

static void dump_process_header(log_t* log, pid_t pid,
                                const std::vector<std::string>& command_line) {
  _LOG(log, logtype::BACKTRACE, "\n\n----- pid %d at %s -----\n", pid, get_timestamp().c_str());

  if (!command_line.empty()) {
    _LOG(log, logtype::BACKTRACE, "Cmd line: %s\n", android::base::Join(command_line, " ").c_str());
  }
  _LOG(log, logtype::BACKTRACE, "ABI: '%s'\n", ABI_STRING);
}

static void dump_process_footer(log_t* log, pid_t pid) {
  _LOG(log, logtype::BACKTRACE, "\n----- end %d -----\n", pid);
}

void dump_backtrace_thread(int output_fd, unwindstack::Unwinder* unwinder,
                           const ThreadInfo& thread) {
  log_t log;
  log.tfd = output_fd;
  log.amfd_data = nullptr;

  _LOG(&log, logtype::BACKTRACE, "\n\"%s\" sysTid=%d\n", thread.thread_name.c_str(), thread.tid);

  unwinder->SetRegs(thread.registers.get());
  unwinder->Unwind();
  if (unwinder->NumFrames() == 0) {
    _LOG(&log, logtype::THREAD, "Unwind failed: tid = %d\n", thread.tid);
    if (unwinder->LastErrorCode() != unwindstack::ERROR_NONE) {
      _LOG(&log, logtype::THREAD, "  Error code: %s\n", unwinder->LastErrorCodeString());
      _LOG(&log, logtype::THREAD, "  Error address: 0x%" PRIx64 "\n", unwinder->LastErrorAddress());
    }
    return;
  }

  log_backtrace(&log, unwinder, "  ");
}

void dump_backtrace(android::base::unique_fd output_fd, unwindstack::Unwinder* unwinder,
                    const std::map<pid_t, ThreadInfo>& thread_info, pid_t target_thread) {
  log_t log;
  log.tfd = output_fd.get();
  log.amfd_data = nullptr;

  auto target = thread_info.find(target_thread);
  if (target == thread_info.end()) {
    ALOGE("failed to find target thread in thread info");
    return;
  }

  dump_process_header(&log, target->second.pid, target->second.command_line);

  dump_backtrace_thread(output_fd.get(), unwinder, target->second);
  for (const auto& [tid, info] : thread_info) {
    if (tid != target_thread) {
      dump_backtrace_thread(output_fd.get(), unwinder, info);
    }
  }

  dump_process_footer(&log, target->second.pid);
}

void dump_backtrace_header(int output_fd) {
  log_t log;
  log.tfd = output_fd;
  log.amfd_data = nullptr;

  pid_t pid = getpid();
  dump_process_header(&log, pid, get_command_line(pid));
}

void dump_backtrace_footer(int output_fd) {
  log_t log;
  log.tfd = output_fd;
  log.amfd_data = nullptr;

  dump_process_footer(&log, getpid());
}
