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

#define LOG_TAG "libbacktrace"

#include <backtrace/backtrace.h>

#include <string.h>

#include <backtrace-arch.h>
#include <cutils/log.h>
#include <corkscrew/backtrace.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <dlfcn.h>

#include "Corkscrew.h"

//-------------------------------------------------------------------------
// CorkscrewCommon functions.
//-------------------------------------------------------------------------
bool CorkscrewCommon::GenerateFrameData(
    backtrace_frame_t* cork_frames, ssize_t num_frames) {
  if (num_frames < 0) {
    BACK_LOGW("libcorkscrew unwind failed.");
    return false;
  }

  backtrace_t* data = GetBacktraceData();
  data->num_frames = num_frames;
  for (size_t i = 0; i < data->num_frames; i++) {
    backtrace_frame_data_t* frame = &data->frames[i];
    frame->num = i;
    frame->pc = cork_frames[i].absolute_pc;
    frame->sp = cork_frames[i].stack_top;
    frame->stack_size = cork_frames[i].stack_size;
    frame->map_name = NULL;
    frame->map_offset = 0;
    frame->func_name = NULL;
    frame->func_offset = 0;

    uintptr_t map_start;
    frame->map_name = backtrace_obj_->GetMapName(frame->pc, &map_start);
    if (frame->map_name) {
      frame->map_offset = frame->pc - map_start;
    }

    std::string func_name = backtrace_obj_->GetFunctionName(frame->pc, &frame->func_offset);
    if (!func_name.empty()) {
      frame->func_name = strdup(func_name.c_str());
    }
  }
  return true;
}

//-------------------------------------------------------------------------
// CorkscrewCurrent functions.
//-------------------------------------------------------------------------
CorkscrewCurrent::CorkscrewCurrent() {
}

CorkscrewCurrent::~CorkscrewCurrent() {
}

bool CorkscrewCurrent::Unwind(size_t num_ignore_frames) {
  backtrace_frame_t frames[MAX_BACKTRACE_FRAMES];
  ssize_t num_frames = unwind_backtrace(frames, num_ignore_frames, MAX_BACKTRACE_FRAMES);

  return GenerateFrameData(frames, num_frames);
}

std::string CorkscrewCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  *offset = 0;

  Dl_info info;
  const backtrace_map_info_t* map_info = backtrace_obj_->FindMapInfo(pc);
  if (map_info) {
    if (dladdr((const void*)pc, &info)) {
      if (info.dli_sname) {
        *offset = pc - map_info->start - (uintptr_t)info.dli_saddr + (uintptr_t)info.dli_fbase;
        return info.dli_sname;
      }
    } else {
      // dladdr(3) didn't find a symbol; maybe it's static? Look in the ELF file...
      symbol_table_t* symbol_table = load_symbol_table(map_info->name);
      if (symbol_table) {
        // First check if we can find the symbol using a relative pc.
        std::string name;
        const symbol_t* elf_symbol = find_symbol(symbol_table, pc - map_info->start);
        if (elf_symbol) {
          name = elf_symbol->name;
          *offset = pc - map_info->start - elf_symbol->start;
        } else if ((elf_symbol = find_symbol(symbol_table, pc)) != NULL) {
          // Found the symbol using the absolute pc.
          name = elf_symbol->name;
          *offset = pc - elf_symbol->start;
        }
        free_symbol_table(symbol_table);
        return name;
      }
    }
  }
  return "";
}

//-------------------------------------------------------------------------
// CorkscrewThread functions.
//-------------------------------------------------------------------------
CorkscrewThread::CorkscrewThread() {
}

CorkscrewThread::~CorkscrewThread() {
  if (corkscrew_map_info_) {
    free_map_info_list(corkscrew_map_info_);
    corkscrew_map_info_ = NULL;
  }
}

bool CorkscrewThread::Init() {
  corkscrew_map_info_ = load_map_info_list(backtrace_obj_->Pid());
  return corkscrew_map_info_ != NULL;
}

void CorkscrewThread::ThreadUnwind(
    siginfo_t* siginfo, void* sigcontext, size_t num_ignore_frames) {
  backtrace_frame_t frames[MAX_BACKTRACE_FRAMES];
  ssize_t num_frames = unwind_backtrace_signal_arch(
      siginfo, sigcontext, corkscrew_map_info_, frames, num_ignore_frames,
      MAX_BACKTRACE_FRAMES);
  if (num_frames > 0) {
    backtrace_t* data = GetBacktraceData();
    data->num_frames = num_frames;
    for (size_t i = 0; i < data->num_frames; i++) {
      backtrace_frame_data_t* frame = &data->frames[i];
      frame->num = i;
      frame->pc = frames[i].absolute_pc;
      frame->sp = frames[i].stack_top;
      frame->stack_size = frames[i].stack_size;

      frame->map_offset = 0;
      frame->map_name = NULL;
      frame->map_offset = 0;

      frame->func_offset = 0;
      frame->func_name = NULL;
    }
  }
}

//-------------------------------------------------------------------------
// CorkscrewPtrace functions.
//-------------------------------------------------------------------------
CorkscrewPtrace::CorkscrewPtrace() : ptrace_context_(NULL) {
}

CorkscrewPtrace::~CorkscrewPtrace() {
  if (ptrace_context_) {
    free_ptrace_context(ptrace_context_);
    ptrace_context_ = NULL;
  }
}

bool CorkscrewPtrace::Unwind(size_t num_ignore_frames) {
  ptrace_context_ = load_ptrace_context(backtrace_obj_->Tid());

  backtrace_frame_t frames[MAX_BACKTRACE_FRAMES];
  ssize_t num_frames = unwind_backtrace_ptrace(
      backtrace_obj_->Tid(), ptrace_context_, frames, num_ignore_frames,
      MAX_BACKTRACE_FRAMES);

  return GenerateFrameData(frames, num_frames);
}

std::string CorkscrewPtrace::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  // Get information about a different process.
  const map_info_t* map_info;
  const symbol_t* symbol;
  find_symbol_ptrace(ptrace_context_, pc, &map_info, &symbol);
  char* symbol_name = NULL;
  if (symbol) {
    if (map_info) {
      *offset = pc - map_info->start - symbol->start;
    }
    symbol_name = symbol->name;
    return symbol_name;
  }

  return "";
}

//-------------------------------------------------------------------------
// C++ object creation functions.
//-------------------------------------------------------------------------
Backtrace* CreateCurrentObj(backtrace_map_info_t* map_info) {
  return new BacktraceCurrent(new CorkscrewCurrent(), map_info);
}

Backtrace* CreatePtraceObj(pid_t pid, pid_t tid, backtrace_map_info_t* map_info) {
  return new BacktracePtrace(new CorkscrewPtrace(), pid, tid, map_info);
}

Backtrace* CreateThreadObj(pid_t tid, backtrace_map_info_t* map_info) {
  CorkscrewThread* thread_obj = new CorkscrewThread();
  return new BacktraceThread(thread_obj, thread_obj, tid, map_info);
}
