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

#ifndef _LIBBACKTRACE_BACKTRACE_H
#define _LIBBACKTRACE_BACKTRACE_H

#include <backtrace/Backtrace.h>

#include <sys/types.h>

class BacktraceImpl {
public:
  virtual ~BacktraceImpl() { }

  virtual bool Unwind(size_t num_ignore_frames) = 0;

  // The name returned is not demangled, Backtrace::GetFunctionName()
  // takes care of demangling the name.
  virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) = 0;

  void SetParent(Backtrace* backtrace) { backtrace_obj_ = backtrace; }

protected:
  backtrace_t* GetBacktraceData();

  Backtrace* backtrace_obj_;
};

class BacktraceCurrent : public Backtrace {
public:
  BacktraceCurrent(BacktraceImpl* impl);
  virtual ~BacktraceCurrent();

  bool ReadWord(uintptr_t ptr, uint32_t* out_value);
};

class BacktracePtrace : public Backtrace {
public:
  BacktracePtrace(BacktraceImpl* impl, pid_t pid, pid_t tid);
  virtual ~BacktracePtrace();

  bool ReadWord(uintptr_t ptr, uint32_t* out_value);
};

Backtrace* CreateCurrentObj();
Backtrace* CreatePtraceObj(pid_t pid, pid_t tid);
Backtrace* CreateThreadObj(pid_t tid);

#endif // _LIBBACKTRACE_BACKTRACE_H
