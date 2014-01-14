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

#ifndef _BACKTRACE_BACKTRACE_H
#define _BACKTRACE_BACKTRACE_H

#include <backtrace/backtrace.h>

#include <string>

class BacktraceImpl;

class Backtrace {
public:
  // Create the correct Backtrace object based on what is to be unwound.
  // If pid < 0 or equals the current pid, then the Backtrace object
  // corresponds to the current process.
  // If pid < 0 or equals the current pid and tid >= 0, then the Backtrace
  // object corresponds to a thread in the current process.
  // If pid >= 0 and tid < 0, then the Backtrace object corresponds to a
  // different process.
  // Tracing a thread in a different process is not supported.
  // If map_info is NULL, then create the map and manage it internally.
  // If map_info is not NULL, the map is still owned by the caller.
  static Backtrace* Create(pid_t pid, pid_t tid, backtrace_map_info_t* map_info = NULL);

  virtual ~Backtrace();

  // Get the current stack trace and store in the backtrace_ structure.
  virtual bool Unwind(size_t num_ignore_frames);

  // Get the function name and offset into the function given the pc.
  // If the string is empty, then no valid function name was found.
  virtual std::string GetFunctionName(uintptr_t pc, uintptr_t* offset);

  // Get the name of the map associated with the given pc. If NULL is returned,
  // then map_start is not set. Otherwise, map_start is the beginning of this
  // map.
  virtual const char* GetMapName(uintptr_t pc, uintptr_t* map_start);

  // Finds the memory map associated with the given ptr.
  virtual const backtrace_map_info_t* FindMapInfo(uintptr_t ptr);

  // Read the data at a specific address.
  virtual bool ReadWord(uintptr_t ptr, uint32_t* out_value) = 0;

  // Create a string representing the formatted line of backtrace information
  // for a single frame.
  virtual std::string FormatFrameData(size_t frame_num);
  virtual std::string FormatFrameData(const backtrace_frame_data_t* frame);

  pid_t Pid() { return backtrace_.pid; }
  pid_t Tid() { return backtrace_.tid; }
  size_t NumFrames() { return backtrace_.num_frames; }

  const backtrace_t* GetBacktrace() { return &backtrace_; }

  const backtrace_frame_data_t* GetFrame(size_t frame_num) {
    if (frame_num > NumFrames()) {
      return NULL;
    }
    return &backtrace_.frames[frame_num];
  }

  const backtrace_map_info_t* GetMapList() {
    return map_info_;
  }

protected:
  Backtrace(BacktraceImpl* impl, pid_t pid, backtrace_map_info_t* map_info);

  virtual bool VerifyReadWordArgs(uintptr_t ptr, uint32_t* out_value);

  BacktraceImpl* impl_;

  backtrace_map_info_t* map_info_;

  bool map_info_requires_delete_;

  backtrace_t backtrace_;

  friend class BacktraceImpl;
};

#endif // _BACKTRACE_BACKTRACE_H
