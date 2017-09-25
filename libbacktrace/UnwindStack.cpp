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
#include <demangle.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/RegsGetLocal.h>

#include "BacktraceLog.h"
#include "UnwindStack.h"
#include "UnwindStackMap.h"

static std::string GetFunctionName(BacktraceMap* back_map, uintptr_t pc, uintptr_t* offset) {
  *offset = 0;
  unwindstack::Maps* maps = reinterpret_cast<UnwindStackMap*>(back_map)->stack_maps();

  // Get the map for this
  unwindstack::MapInfo* map_info = maps->Find(pc);
  if (map_info == nullptr || map_info->flags & PROT_DEVICE_MAP) {
    return "";
  }

  UnwindStackMap* stack_map = reinterpret_cast<UnwindStackMap*>(back_map);
  unwindstack::Elf* elf = map_info->GetElf(stack_map->process_memory(), true);

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

static void SetFrameInfo(unwindstack::Regs* regs, unwindstack::MapInfo* map_info,
                         uint64_t adjusted_rel_pc, backtrace_frame_data_t* frame) {
  // This will point to the adjusted absolute pc. regs->pc() is
  // unaltered.
  frame->pc = map_info->start + adjusted_rel_pc;
  frame->sp = regs->sp();
  frame->rel_pc = adjusted_rel_pc;
  frame->stack_size = 0;

  frame->map.start = map_info->start;
  frame->map.end = map_info->end;
  frame->map.offset = map_info->offset;
  frame->map.flags = map_info->flags;
  frame->map.name = map_info->name;

  unwindstack::Elf* elf = map_info->elf;
  frame->map.load_bias = elf->GetLoadBias();
  uint64_t func_offset = 0;
  if (elf->GetFunctionName(adjusted_rel_pc, &frame->func_name, &func_offset)) {
    frame->func_name = demangle(frame->func_name.c_str());
  } else {
    frame->func_name = "";
  }
  frame->func_offset = func_offset;
}

static bool Unwind(unwindstack::Regs* regs, BacktraceMap* back_map,
                   std::vector<backtrace_frame_data_t>* frames, size_t num_ignore_frames) {
  UnwindStackMap* stack_map = reinterpret_cast<UnwindStackMap*>(back_map);
  unwindstack::Maps* maps = stack_map->stack_maps();
  bool adjust_rel_pc = false;
  size_t num_frames = 0;
  frames->clear();
  bool return_address_attempted = false;
  auto process_memory = stack_map->process_memory();
  while (num_frames < MAX_BACKTRACE_FRAMES) {
    unwindstack::MapInfo* map_info = maps->Find(regs->pc());
    bool stepped;
    bool in_device_map = false;
    if (map_info == nullptr) {
      stepped = false;
      if (num_ignore_frames == 0) {
        frames->resize(num_frames + 1);
        backtrace_frame_data_t* frame = &frames->at(num_frames);
        frame->pc = regs->pc();
        frame->sp = regs->sp();
        frame->rel_pc = frame->pc;
        num_frames++;
      } else {
        num_ignore_frames--;
      }
    } else {
      unwindstack::Elf* elf = map_info->GetElf(process_memory, true);
      uint64_t rel_pc = elf->GetRelPc(regs->pc(), map_info);

      if (frames->size() != 0 || !IsUnwindLibrary(map_info->name)) {
        if (num_ignore_frames == 0) {
          uint64_t adjusted_rel_pc = rel_pc;
          if (adjust_rel_pc) {
            adjusted_rel_pc = regs->GetAdjustedPc(rel_pc, elf);
          }

          frames->resize(num_frames + 1);
          backtrace_frame_data_t* frame = &frames->at(num_frames);
          frame->num = num_frames;
          SetFrameInfo(regs, map_info, adjusted_rel_pc, frame);

          if (num_frames > 0) {
            // Set the stack size for the previous frame.
            backtrace_frame_data_t* prev = &frames->at(num_frames - 1);
            prev->stack_size = frame->sp - prev->sp;
          }
          num_frames++;
        } else {
          num_ignore_frames--;
        }
      }

      if (map_info->flags & PROT_DEVICE_MAP) {
        // Do not stop here, fall through in case we are
        // in the speculative unwind path and need to remove
        // some of the speculative frames.
        stepped = false;
        in_device_map = true;
      } else {
        unwindstack::MapInfo* sp_info = maps->Find(regs->sp());
        if (sp_info->flags & PROT_DEVICE_MAP) {
          // Do not stop here, fall through in case we are
          // in the speculative unwind path and need to remove
          // some of the speculative frames.
          stepped = false;
          in_device_map = true;
        } else {
          bool finished;
          stepped = elf->Step(rel_pc + map_info->elf_offset, regs, process_memory.get(), &finished);
          if (stepped && finished) {
            break;
          }
        }
      }
    }
    adjust_rel_pc = true;

    if (!stepped) {
      if (return_address_attempted) {
        // Remove the speculative frame.
        if (frames->size() > 0) {
          frames->pop_back();
        }
        break;
      } else if (in_device_map) {
        // Do not attempt any other unwinding, pc or sp is in a device
        // map.
        break;
      } else {
        // Stepping didn't work, try this secondary method.
        if (!regs->SetPcFromReturnAddress(process_memory.get())) {
          break;
        }
        return_address_attempted = true;
      }
    } else {
      return_address_attempted = false;
    }
  }

  return true;
}

UnwindStackCurrent::UnwindStackCurrent(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktraceCurrent(pid, tid, map) {}

std::string UnwindStackCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return ::GetFunctionName(GetMap(), pc, offset);
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
  return ::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames);
}

UnwindStackPtrace::UnwindStackPtrace(pid_t pid, pid_t tid, BacktraceMap* map)
    : BacktracePtrace(pid, tid, map) {}

std::string UnwindStackPtrace::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  return ::GetFunctionName(GetMap(), pc, offset);
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
  return ::Unwind(regs.get(), GetMap(), &frames_, num_ignore_frames);
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
