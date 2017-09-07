/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define _GNU_SOURCE 1
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ucontext.h>

#include <memory>
#include <set>
#include <string>

#if !defined(__ANDROID__)
#include <cutils/threads.h>
#endif

#include <backtrace/Backtrace.h>
#include <demangle.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>

#include <unwindstack/Unwinder.h>

#include "BacktraceLog.h"
#include "UnwindStack.h"
#include "UnwindStackMap.h"

bool Backtrace::Unwind(unwindstack::Regs* regs, BacktraceMap* back_map,
                       std::vector<backtrace_frame_data_t>* frames, size_t num_ignore_frames) {
  static std::set<std::string> skip_names{"libunwindstack.so", "libbacktrace.so"};
  UnwindStackMap* stack_map = reinterpret_cast<UnwindStackMap*>(back_map);
  auto process_memory = stack_map->process_memory();
  unwindstack::Unwinder unwinder(MAX_BACKTRACE_FRAMES + num_ignore_frames, stack_map->stack_maps(),
                                 regs, stack_map->process_memory());
  unwinder.Unwind(&skip_names);

  if (num_ignore_frames >= unwinder.NumFrames()) {
    frames->resize(0);
    return true;
  }

  frames->resize(unwinder.NumFrames() - num_ignore_frames);
  auto unwinder_frames = unwinder.frames();
  size_t cur_frame = 0;
  for (size_t i = num_ignore_frames; i < unwinder.NumFrames(); i++, cur_frame++) {
    auto frame = &unwinder_frames[i];
    backtrace_frame_data_t* back_frame = &frames->at(cur_frame);

    back_frame->num = frame->num;

    back_frame->rel_pc = frame->rel_pc;
    back_frame->pc = frame->pc;
    back_frame->sp = frame->sp;

    back_frame->func_name = frame->function_name;
    back_frame->func_offset = frame->function_offset;

    back_frame->map.name = frame->map_name;
    back_frame->map.start = frame->map_start;
    back_frame->map.end = frame->map_end;
    back_frame->map.offset = frame->map_offset;
    back_frame->map.load_bias = frame->map_load_bias;
    back_frame->map.flags = frame->map_flags;
  }

  return true;
}

UnwindStackCurrent::UnwindStackCurrent(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktraceCurrent(pid, tid, map) {}

std::string UnwindStackCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return GetMap()->GetFunctionName(pc, offset);
}

bool UnwindStackCurrent::UnwindFromContext(size_t num_ignore_frames, ucontext_t* ucontext) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (ucontext == nullptr) {
    regs.reset(unwindstack::Regs::CreateFromLocal());
    // Fill in the registers from this function. Do it here to avoid
    // one extra function call appearing in the unwind.
    unwindstack::RegsGetLocal(regs.get());
  } else {
    regs.reset(
        unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentMachineType(), ucontext));
  }

  error_ = BACKTRACE_UNWIND_NO_ERROR;
  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames);
}

UnwindStackPtrace::UnwindStackPtrace(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktracePtrace(pid, tid, map) {}

std::string UnwindStackPtrace::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return GetMap()->GetFunctionName(pc, offset);
}

bool UnwindStackPtrace::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (context == nullptr) {
    regs.reset(unwindstack::Regs::RemoteGet(Tid()));
  } else {
    regs.reset(
        unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentMachineType(), context));
  }

  error_ = BACKTRACE_UNWIND_NO_ERROR;
  return Backtrace::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames);
}

Backtrace* Backtrace::CreateNew(pid_t pid, pid_t tid, BacktraceMap* map) {
  if (pid == BACKTRACE_CURRENT_PROCESS) {
    pid = getpid();
    if (tid == BACKTRACE_CURRENT_THREAD) {
      tid = gettid();
    }
  } else if (tid == BACKTRACE_CURRENT_THREAD) {
    tid = pid;
  }

  if (map == nullptr) {
// This would cause the wrong type of map object to be created, so disallow.
#if defined(__ANDROID__)
    __assert2(__FILE__, __LINE__, __PRETTY_FUNCTION__,
              "Backtrace::CreateNew() must be called with a real map pointer.");
#else
    BACK_LOGE("Backtrace::CreateNew() must be called with a real map pointer.");
    abort();
#endif
  }

  if (pid == getpid()) {
    return new UnwindStackCurrent(pid, tid, map);
  } else {
    return new UnwindStackPtrace(pid, tid, map);
  }
}
