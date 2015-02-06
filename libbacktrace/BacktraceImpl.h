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

#ifndef _LIBBACKTRACE_BACKTRACE_IMPL_H
#define _LIBBACKTRACE_BACKTRACE_IMPL_H

#include <backtrace/Backtrace.h>
#include <backtrace/BacktraceMap.h>

#include <sys/types.h>

class BacktraceImpl {
public:
  virtual ~BacktraceImpl() { }

  virtual bool Unwind(size_t num_ignore_frames, ucontext_t* ucontext) = 0;

  // The name returned is not demangled, Backtrace::GetFunctionName()
  // takes care of demangling the name.
  virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) = 0;

  void SetParent(Backtrace* backtrace) { backtrace_obj_ = backtrace; }

  inline pid_t Pid() { return backtrace_obj_->Pid(); }
  inline pid_t Tid() { return backtrace_obj_->Tid(); }

  inline void FillInMap(uintptr_t addr, backtrace_map_t* map) {
    backtrace_obj_->FillInMap(addr, map);
  }
  inline std::string GetFunctionName(uintptr_t pc, uintptr_t* offset) {
    return backtrace_obj_->GetFunctionName(pc, offset);
  }
  inline BacktraceMap* GetMap() { return backtrace_obj_->GetMap(); }

protected:
  inline std::vector<backtrace_frame_data_t>* GetFrames() { return &backtrace_obj_->frames_; }

  Backtrace* backtrace_obj_;
};

class BacktraceCurrent : public Backtrace {
public:
  BacktraceCurrent(BacktraceImpl* impl, BacktraceMap* map);
  virtual ~BacktraceCurrent();

  bool ReadWord(uintptr_t ptr, word_t* out_value);
};

class BacktracePtrace : public Backtrace {
public:
  BacktracePtrace(BacktraceImpl* impl, pid_t pid, pid_t tid, BacktraceMap* map);
  virtual ~BacktracePtrace();

  bool ReadWord(uintptr_t ptr, word_t* out_value);
};

Backtrace* CreateCurrentObj(BacktraceMap* map);
Backtrace* CreatePtraceObj(pid_t pid, pid_t tid, BacktraceMap* map);
Backtrace* CreateThreadObj(pid_t tid, BacktraceMap* map);

#endif // _LIBBACKTRACE_BACKTRACE_IMPL_H
