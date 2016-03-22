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

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <ucontext.h>
#include <unistd.h>

#include <string>

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include "BacktraceImpl.h"
#include "BacktraceLog.h"
#include "thread_utils.h"

//-------------------------------------------------------------------------
// Backtrace functions.
//-------------------------------------------------------------------------
Backtrace::Backtrace(BacktraceImpl* impl, pid_t pid, BacktraceMap* map)
    : pid_(pid), tid_(-1), map_(map), map_shared_(true), impl_(impl) {
  impl_->SetParent(this);

  if (map_ == NULL) {
    map_ = BacktraceMap::Create(pid);
    map_shared_ = false;
  }
}

Backtrace::~Backtrace() {
  if (impl_) {
    delete impl_;
    impl_ = NULL;
  }

  if (map_ && !map_shared_) {
    delete map_;
    map_ = NULL;
  }
}

bool Backtrace::Unwind(size_t num_ignore_frames, ucontext_t* ucontext) {
  return impl_->Unwind(num_ignore_frames, ucontext);
}

std::string Backtrace::GetFunctionName(uintptr_t pc, uintptr_t* offset) {
  std::string func_name = impl_->GetFunctionNameRaw(pc, offset);
  return func_name;
}

bool Backtrace::VerifyReadWordArgs(uintptr_t ptr, word_t* out_value) {
  if (ptr & (sizeof(word_t)-1)) {
    BACK_LOGW("invalid pointer %p", (void*)ptr);
    *out_value = (word_t)-1;
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
  if (frame->map && !frame->map->name.empty()) {
    map_name = frame->map->name.c_str();
  } else {
    map_name = "<unknown>";
  }

  uintptr_t relative_pc;
  if (frame->map) {
    relative_pc = frame->pc - frame->map->start;
  } else {
    relative_pc = frame->pc;
  }

  char buf[512];
  if (!frame->func_name.empty() && frame->func_offset) {
    snprintf(buf, sizeof(buf), "#%02zu pc %0*" PRIxPTR "  %s (%s+%" PRIuPTR ")",
             frame->num, (int)sizeof(uintptr_t)*2, relative_pc, map_name,
             frame->func_name.c_str(), frame->func_offset);
  } else if (!frame->func_name.empty()) {
    snprintf(buf, sizeof(buf), "#%02zu pc %0*" PRIxPTR "  %s (%s)", frame->num,
             (int)sizeof(uintptr_t)*2, relative_pc, map_name, frame->func_name.c_str());
  } else {
    snprintf(buf, sizeof(buf), "#%02zu pc %0*" PRIxPTR "  %s", frame->num,
             (int)sizeof(uintptr_t)*2, relative_pc, map_name);
  }

  return buf;
}

const backtrace_map_t* Backtrace::FindMap(uintptr_t pc) {
  return map_->Find(pc);
}

//-------------------------------------------------------------------------
// BacktraceCurrent functions.
//-------------------------------------------------------------------------
BacktraceCurrent::BacktraceCurrent(
    BacktraceImpl* impl, BacktraceMap* map) : Backtrace(impl, getpid(), map) {
}

BacktraceCurrent::~BacktraceCurrent() {
}

bool BacktraceCurrent::ReadWord(uintptr_t ptr, word_t* out_value) {
  if (!VerifyReadWordArgs(ptr, out_value)) {
    return false;
  }

  const backtrace_map_t* map = FindMap(ptr);
  if (map && map->flags & PROT_READ) {
    *out_value = *reinterpret_cast<word_t*>(ptr);
    return true;
  } else {
    BACK_LOGW("pointer %p not in a readable map", reinterpret_cast<void*>(ptr));
    *out_value = static_cast<word_t>(-1);
    return false;
  }
}

//-------------------------------------------------------------------------
// BacktracePtrace functions.
//-------------------------------------------------------------------------
BacktracePtrace::BacktracePtrace(
    BacktraceImpl* impl, pid_t pid, pid_t tid, BacktraceMap* map)
    : Backtrace(impl, pid, map) {
  tid_ = tid;
}

BacktracePtrace::~BacktracePtrace() {
}

bool BacktracePtrace::ReadWord(uintptr_t ptr, word_t* out_value) {
  if (!VerifyReadWordArgs(ptr, out_value)) {
    return false;
  }

#if defined(__APPLE__)
  BACK_LOGW("MacOS does not support reading from another pid.");
  return false;
#else
  // ptrace() returns -1 and sets errno when the operation fails.
  // To disambiguate -1 from a valid result, we clear errno beforehand.
  errno = 0;
  *out_value = ptrace(PTRACE_PEEKTEXT, Tid(), reinterpret_cast<void*>(ptr), NULL);
  if (*out_value == static_cast<word_t>(-1) && errno) {
    BACK_LOGW("invalid pointer %p reading from tid %d, ptrace() strerror(errno)=%s",
              reinterpret_cast<void*>(ptr), Tid(), strerror(errno));
    return false;
  }
  return true;
#endif
}

Backtrace* Backtrace::Create(pid_t pid, pid_t tid, BacktraceMap* map) {
  if (pid == BACKTRACE_CURRENT_PROCESS || pid == getpid()) {
    if (tid == BACKTRACE_CURRENT_THREAD || tid == gettid()) {
      return CreateCurrentObj(map);
    } else {
      return CreateThreadObj(tid, map);
    }
  } else if (tid == BACKTRACE_CURRENT_THREAD) {
    return CreatePtraceObj(pid, pid, map);
  } else {
    return CreatePtraceObj(pid, tid, map);
  }
}
