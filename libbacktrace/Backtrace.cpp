/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <ucontext.h>

#include <string>

#include <base/stringprintf.h>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include <cutils/threads.h>

#include "BacktraceLog.h"
#include "thread_utils.h"
#include "UnwindCurrent.h"
#include "UnwindPtrace.h"

using android::base::StringPrintf;

//-------------------------------------------------------------------------
// Backtrace functions.
//-------------------------------------------------------------------------
Backtrace::Backtrace(pid_t pid, pid_t tid, BacktraceMap* map)
    : pid_(pid), tid_(tid), map_(map), map_shared_(true) {
  if (map_ == nullptr) {
    map_ = BacktraceMap::Create(pid);
    map_shared_ = false;
  }
}

Backtrace::~Backtrace() {
  if (map_ && !map_shared_) {
    delete map_;
    map_ = nullptr;
  }
}

extern "C" char* __cxa_demangle(const char* mangled, char* buf, size_t* len,
                                int* status);

std::string Backtrace::GetFunctionName(uintptr_t pc, uintptr_t* offset) {
  std::string func_name = GetFunctionNameRaw(pc, offset);
  if (!func_name.empty()) {
#if defined(__APPLE__)
    // Mac OS' __cxa_demangle demangles "f" as "float"; last tested on 10.7.
    if (func_name[0] != '_') {
      return func_name;
    }
#endif
    char* name = __cxa_demangle(func_name.c_str(), 0, 0, 0);
    if (name) {
      func_name = name;
      free(name);
    }
  }
  return func_name;
}

bool Backtrace::VerifyReadWordArgs(uintptr_t ptr, word_t* out_value) {
  if (ptr & (sizeof(word_t)-1)) {
    BACK_LOGW("invalid pointer %p", reinterpret_cast<void*>(ptr));
    *out_value = static_cast<word_t>(-1);
    return false;
  }
  return true;
}

std::string Backtrace::FormatFrameData(size_t frame_num) {
  if (frame_num >= frames_.size()) {
    return "";
  }
  return FormatFrameData(&frames_[frame_num]);
}

std::string Backtrace::FormatFrameData(const backtrace_frame_data_t* frame) {
  const char* map_name;
  if (BacktraceMap::IsValid(frame->map) && !frame->map.name.empty()) {
    map_name = frame->map.name.c_str();
  } else {
    map_name = "<unknown>";
  }

  uintptr_t relative_pc = BacktraceMap::GetRelativePc(frame->map, frame->pc);

  std::string line(StringPrintf("#%02zu pc %" PRIPTR "  %s", frame->num, relative_pc, map_name));
  // Special handling for non-zero offset maps, we need to print that
  // information.
  if (frame->map.offset != 0) {
    line += " (offset " + StringPrintf("0x%" PRIxPTR, frame->map.offset) + ")";
  }
  if (!frame->func_name.empty()) {
    line += " (" + frame->func_name;
    if (frame->func_offset) {
      line += StringPrintf("+%" PRIuPTR, frame->func_offset);
    }
    line += ')';
  }

  return line;
}

void Backtrace::FillInMap(uintptr_t pc, backtrace_map_t* map) {
  if (map_ != nullptr) {
    map_->FillIn(pc, map);
  }
}

Backtrace* Backtrace::Create(pid_t pid, pid_t tid, BacktraceMap* map) {
  if (pid == BACKTRACE_CURRENT_PROCESS) {
    pid = getpid();
    if (tid == BACKTRACE_CURRENT_THREAD) {
      tid = gettid();
    }
  } else if (tid == BACKTRACE_CURRENT_THREAD) {
    tid = pid;
  }

  if (pid == getpid()) {
    return new UnwindCurrent(pid, tid, map);
  } else {
    return new UnwindPtrace(pid, tid, map);
  }
}
