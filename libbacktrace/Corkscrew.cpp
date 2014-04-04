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

#include <backtrace/Backtrace.h>

#include <string.h>

#include <backtrace-arch.h>
#include <corkscrew/backtrace.h>

#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <dlfcn.h>

#include "BacktraceLog.h"
#include "Corkscrew.h"

//-------------------------------------------------------------------------
// CorkscrewMap functions.
//-------------------------------------------------------------------------
CorkscrewMap::CorkscrewMap(pid_t pid) : BacktraceMap(pid), map_info_(NULL) {
}

CorkscrewMap::~CorkscrewMap() {
  if (map_info_) {
    free_map_info_list(map_info_);
    map_info_ = NULL;
  }
}

bool CorkscrewMap::Build() {
  map_info_ = load_map_info_list(pid_);

  // Use the information in map_info_ to construct the BacktraceMap data
  // rather than reparsing /proc/self/maps.
  map_info_t* cur_map = map_info_;
  while (cur_map) {
    backtrace_map_t map;
    map.start = cur_map->start;
    map.end = cur_map->end;
    map.flags = 0;
    if (cur_map->is_readable) {
      map.flags |= PROT_READ;
    }
    if (cur_map->is_writable) {
      map.flags |= PROT_WRITE;
    }
    if (cur_map->is_executable) {
      map.flags |= PROT_EXEC;
    }
    map.name = cur_map->name;

    // The maps are in descending order, but we want them in ascending order.
    maps_.push_front(map);

    cur_map = cur_map->next;
  }
  return map_info_ != NULL;
}

//-------------------------------------------------------------------------
// CorkscrewCommon functions.
//-------------------------------------------------------------------------
bool CorkscrewCommon::GenerateFrameData(
    backtrace_frame_t* cork_frames, ssize_t num_frames) {
  if (num_frames < 0) {
    BACK_LOGW("libcorkscrew unwind failed.");
    return false;
  }

  std::vector<backtrace_frame_data_t>* frames = GetFrames();
  frames->resize(num_frames);
  size_t i = 0;
  for (std::vector<backtrace_frame_data_t>::iterator it = frames->begin();
       it != frames->end(); ++it, ++i) {
    it->num = i;
    it->pc = cork_frames[i].absolute_pc;
    it->sp = cork_frames[i].stack_top;
    it->stack_size = cork_frames[i].stack_size;
    it->func_offset = 0;

    it->map = FindMap(it->pc);
    it->func_name = GetFunctionName(it->pc, &it->func_offset);
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
  const backtrace_map_t* map = FindMap(pc);
  if (map) {
    if (dladdr((const void*)pc, &info)) {
      if (info.dli_sname) {
        *offset = pc - map->start - (uintptr_t)info.dli_saddr + (uintptr_t)info.dli_fbase;
        return info.dli_sname;
      }
    } else {
      // dladdr(3) didn't find a symbol; maybe it's static? Look in the ELF file...
      symbol_table_t* symbol_table = load_symbol_table(map->name.c_str());
      if (symbol_table) {
        // First check if we can find the symbol using a relative pc.
        std::string name;
        const symbol_t* elf_symbol = find_symbol(symbol_table, pc - map->start);
        if (elf_symbol) {
          name = elf_symbol->name;
          *offset = pc - map->start - elf_symbol->start;
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
}

void CorkscrewThread::ThreadUnwind(
    siginfo_t* siginfo, void* sigcontext, size_t num_ignore_frames) {
  backtrace_frame_t cork_frames[MAX_BACKTRACE_FRAMES];
  CorkscrewMap* map = static_cast<CorkscrewMap*>(GetMap());
  ssize_t num_frames = unwind_backtrace_signal_arch(
      siginfo, sigcontext, map->GetMapInfo(), cork_frames,
      num_ignore_frames, MAX_BACKTRACE_FRAMES);
  if (num_frames > 0) {
    std::vector<backtrace_frame_data_t>* frames = GetFrames();
    frames->resize(num_frames);
    size_t i = 0;
    for (std::vector<backtrace_frame_data_t>::iterator it = frames->begin();
         it != frames->end(); ++it, ++i) {
      it->num = i;
      it->pc = cork_frames[i].absolute_pc;
      it->sp = cork_frames[i].stack_top;
      it->stack_size = cork_frames[i].stack_size;
      it->map = NULL;
      it->func_offset = 0;
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
  ptrace_context_ = load_ptrace_context(Tid());

  backtrace_frame_t frames[MAX_BACKTRACE_FRAMES];
  ssize_t num_frames = unwind_backtrace_ptrace(
      Tid(), ptrace_context_, frames, num_ignore_frames, MAX_BACKTRACE_FRAMES);

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
Backtrace* CreateCurrentObj(BacktraceMap* map) {
  return new BacktraceCurrent(new CorkscrewCurrent(), map);
}

Backtrace* CreatePtraceObj(pid_t pid, pid_t tid, BacktraceMap* map) {
  return new BacktracePtrace(new CorkscrewPtrace(), pid, tid, map);
}

Backtrace* CreateThreadObj(pid_t tid, BacktraceMap* map) {
  CorkscrewThread* thread_obj = new CorkscrewThread();
  return new BacktraceThread(thread_obj, thread_obj, tid, map);
}

//-------------------------------------------------------------------------
// BacktraceMap create function.
//-------------------------------------------------------------------------
BacktraceMap* BacktraceMap::Create(pid_t pid) {
  BacktraceMap* map = new CorkscrewMap(pid);
  if (!map->Build()) {
    delete map;
    return NULL;
  }
  return map;
}
