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

#ifndef _LIBBACKTRACE_UNWIND_PTRACE_H
#define _LIBBACKTRACE_UNWIND_PTRACE_H

#include <string>

#include "BacktraceImpl.h"

#include <libunwind.h>

class UnwindPtrace : public BacktraceImpl {
public:
  UnwindPtrace();
  virtual ~UnwindPtrace();

  virtual bool Unwind(size_t num_ignore_frames, ucontext_t* ucontext);

  virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset);

private:
  unw_addr_space_t addr_space_;
  struct UPT_info* upt_info_;
};

#endif // _LIBBACKTRACE_UNWIND_PTRACE_H
