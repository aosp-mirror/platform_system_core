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

  // Get information about the current thread.
  Dl_info info;
  const backtrace_map_info_t* map_info = backtrace_obj_->FindMapInfo(pc);
  const char* symbol_name = NULL;
  if (map_info && dladdr((const void*)pc, &info) && info.dli_sname) {
    *offset = pc - map_info->start - (uintptr_t)info.dli_saddr + (uintptr_t)info.dli_fbase;
    symbol_name = info.dli_sname;

    return symbol_name;
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
Backtrace* CreateCurrentObj() {
  return new BacktraceCurrent(new CorkscrewCurrent());
}

Backtrace* CreatePtraceObj(pid_t pid, pid_t tid) {
  return new BacktracePtrace(new CorkscrewPtrace(), pid, tid);
}

Backtrace* CreateThreadObj(pid_t tid) {
  CorkscrewThread* thread_obj = new CorkscrewThread();
  return new BacktraceThread(thread_obj, thread_obj, tid);
}
