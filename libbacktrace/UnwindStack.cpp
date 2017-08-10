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
#include <string>

#if !defined(__ANDROID__)
#include <cutils/threads.h>
#endif

#include <backtrace/Backtrace.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>

#include "BacktraceLog.h"
#include "UnwindStack.h"
#include "UnwindStackMap.h"

static std::string GetFunctionName(pid_t pid, BacktraceMap* back_map, uintptr_t pc,
                                   uintptr_t* offset) {
  *offset = 0;
  unwindstack::Maps* maps = reinterpret_cast<UnwindStackMap*>(back_map)->stack_maps();

  // Get the map for this
  unwindstack::MapInfo* map_info = maps->Find(pc);
  if (map_info == nullptr || map_info->flags & PROT_DEVICE_MAP) {
    return "";
  }

  unwindstack::Elf* elf = map_info->GetElf(pid, true);

  std::string name;
  uint64_t func_offset;
  if (!elf->GetFunctionName(elf->GetRelPc(pc, map_info), &name, &func_offset)) {
    return "";
  }
  *offset = func_offset;
  return name;
}

static bool IsUnwindLibrary(const std::string& map_name) {
  const std::string library(basename(map_name.c_str()));
  return library == "libunwindstack.so" || library == "libbacktrace.so";
}

static bool Unwind(pid_t pid, unwindstack::Memory* memory, unwindstack::Regs* regs,
                   BacktraceMap* back_map, std::vector<backtrace_frame_data_t>* frames,
                   size_t num_ignore_frames) {
  unwindstack::Maps* maps = reinterpret_cast<UnwindStackMap*>(back_map)->stack_maps();
  bool adjust_rel_pc = false;
  size_t num_frames = 0;
  frames->clear();
  while (num_frames < MAX_BACKTRACE_FRAMES) {
    if (regs->pc() == 0) {
      break;
    }
    unwindstack::MapInfo* map_info = maps->Find(regs->pc());
    if (map_info == nullptr) {
      break;
    }

    unwindstack::Elf* elf = map_info->GetElf(pid, true);
    uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);

    bool skip_frame = num_frames == 0 && IsUnwindLibrary(map_info->name);
    if (num_ignore_frames == 0 && !skip_frame) {
      uint64_t adjusted_rel_pc = rel_pc;
      if (adjust_rel_pc) {
        adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
      }
      frames->resize(num_frames + 1);
      backtrace_frame_data_t* frame = &frames->at(num_frames);
      frame->num = num_frames;
      // This will point to the adjusted absolute pc. regs->pc() is
      // unaltered.
      frame->pc = map_info->start + adjusted_rel_pc;
      frame->sp = regs->sp();
      frame->rel_pc = adjusted_rel_pc;
      frame->stack_size = 0;

      frame->map.start = map_info->start;
      frame->map.end = map_info->end;
      frame->map.offset = map_info->offset;
      frame->map.load_bias = elf->GetLoadBias();
      frame->map.flags = map_info->flags;
      frame->map.name = map_info->name;

      uint64_t func_offset = 0;
      if (!elf->GetFunctionName(adjusted_rel_pc, &frame->func_name, &func_offset)) {
        frame->func_name = "";
      }
      frame->func_offset = func_offset;
      if (num_frames > 0) {
        // Set the stack size for the previous frame.
        backtrace_frame_data_t* prev = &frames->at(num_frames - 1);
        prev->stack_size = frame->sp - prev->sp;
      }
      num_frames++;
    } else if (!skip_frame && num_ignore_frames > 0) {
      num_ignore_frames--;
    }
    adjust_rel_pc = true;

    // Do not unwind through a device map.
    if (map_info->flags & PROT_DEVICE_MAP) {
      break;
    }
    unwindstack::MapInfo* sp_info = maps->Find(regs->sp());
    if (sp_info->flags & PROT_DEVICE_MAP) {
      break;
    }

    if (!elf->Step(rel_pc + map_info->elf_offset, regs, memory)) {
      break;
    }
  }

  return true;
}

UnwindStackCurrent::UnwindStackCurrent(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktraceCurrent(pid, tid, map), memory_(new unwindstack::MemoryLocal) {}

std::string UnwindStackCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return ::GetFunctionName(Pid(), GetMap(), pc, offset);
}

bool UnwindStackCurrent::UnwindFromContext(size_t num_ignore_frames, ucontext_t* ucontext) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (ucontext == nullptr) {
    regs.reset(unwindstack::Regs::CreateFromLocal());
    // Fill in the registers from this function. Do it here to avoid
    // one extra function call appearing in the unwind.
    unwindstack::RegsGetLocal(regs.get());
  } else {
    regs.reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::GetMachineType(), ucontext));
  }

  error_ = BACKTRACE_UNWIND_NO_ERROR;
  return ::Unwind(getpid(), memory_.get(), regs.get(), GetMap(), &frames_, num_ignore_frames);
}

UnwindStackPtrace::UnwindStackPtrace(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktracePtrace(pid, tid, map), memory_(new unwindstack::MemoryRemote(pid)) {}

std::string UnwindStackPtrace::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return ::GetFunctionName(Pid(), GetMap(), pc, offset);
}

bool UnwindStackPtrace::Unwind(size_t num_ignore_frames, ucontext_t* context) {
  std::unique_ptr<unwindstack::Regs> regs;
  if (context == nullptr) {
    uint32_t machine_type;
    regs.reset(unwindstack::Regs::RemoteGet(Tid(), &machine_type));
  } else {
    regs.reset(unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::GetMachineType(), context));
  }

  error_ = BACKTRACE_UNWIND_NO_ERROR;
  return ::Unwind(Pid(), memory_.get(), regs.get(), GetMap(), &frames_, num_ignore_frames);
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
