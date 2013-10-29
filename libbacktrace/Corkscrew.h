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

#ifndef _LIBBACKTRACE_CORKSCREW_H
#define _LIBBACKTRACE_CORKSCREW_H

#include <inttypes.h>

#include <string>

#include <backtrace/backtrace.h>
#include <backtrace/Backtrace.h>

#include <corkscrew/backtrace.h>

#include "Backtrace.h"
#include "BacktraceThread.h"

class CorkscrewCommon : public BacktraceImpl {
public:
  bool GenerateFrameData(backtrace_frame_t* cork_frames, ssize_t num_frames);
};

class CorkscrewCurrent : public CorkscrewCommon {
public:
  CorkscrewCurrent();
  virtual ~CorkscrewCurrent();

  virtual bool Unwind(size_t num_ignore_threads);

  virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset);
};

class CorkscrewThread : public CorkscrewCurrent, public BacktraceThreadInterface {
public:
  CorkscrewThread();
  virtual ~CorkscrewThread();

  virtual bool Init();

  virtual void ThreadUnwind(
      siginfo_t* siginfo, void* sigcontext, size_t num_ignore_frames);

private:
  map_info_t* corkscrew_map_info_;
};

class CorkscrewPtrace : public CorkscrewCommon {
public:
  CorkscrewPtrace();
  virtual ~CorkscrewPtrace();

  virtual std::string GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset);

  virtual bool Unwind(size_t num_ignore_threads);

private:
  ptrace_context_t* ptrace_context_;
};

#endif // _LIBBACKTRACE_CORKSCREW_H
