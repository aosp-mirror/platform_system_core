/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef _LIBBACKTRACE_UNWIND_OFFLINE_H
#define _LIBBACKTRACE_UNWIND_OFFLINE_H

#include <libunwind.h>
#include <stdint.h>
#include <sys/types.h>
#include <ucontext.h>

#include <unordered_map>
#include <unordered_set>

#include <backtrace/Backtrace.h>

struct Space {
  uint64_t start;
  uint64_t end;
  const uint8_t* data;

  Space() { Clear(); }

  void Clear();
  size_t Read(uint64_t addr, uint8_t* buffer, size_t size);
};

struct DebugFrameInfo;

class BacktraceOffline : public Backtrace {
 public:
  BacktraceOffline(pid_t pid, pid_t tid, BacktraceMap* map, const backtrace_stackinfo_t& stack,
                   bool cache_file)
      : Backtrace(pid, tid, map),
        cache_file_(cache_file),
        context_(nullptr),
        is_debug_frame_used_(false) {
    stack_space_.start = stack.start;
    stack_space_.end = stack.end;
    stack_space_.data = stack.data;
  }

  virtual ~BacktraceOffline() = default;

  bool Unwind(size_t num_ignore_frames, ucontext_t* context) override;

  bool ReadWord(uint64_t ptr, word_t* out_value) override;

  size_t Read(uint64_t addr, uint8_t* buffer, size_t bytes) override;

  bool FindProcInfo(unw_addr_space_t addr_space, uint64_t ip, unw_proc_info_t* proc_info,
                    int need_unwind_info);

  bool ReadReg(size_t reg_index, uint64_t* value);

 protected:
  std::string GetFunctionNameRaw(uint64_t pc, uint64_t* offset) override;
  DebugFrameInfo* GetDebugFrameInFile(const std::string& filename);

  bool cache_file_;
  ucontext_t* context_;
  Space eh_frame_hdr_space_;
  Space eh_frame_space_;
  Space arm_extab_space_;
  Space arm_exidx_space_;
  Space stack_space_;

  // is_debug_frame_used_ is to make sure we can try both .debug_frame and .ARM.exidx in
  // FindProcInfo() on ARM. One example is EsxContext::Clear() in
  // vendor/lib/egl/libGLESv2_adreno.so. EsxContext::Clear() appears in both .debug_frame and
  // .ARM.exidx. However, libunwind fails to execute debug_frame instruction
  // "DW_CFA_offset_extended: r265 at cfa-48". So we need to try .ARM.exidx to unwind that
  // function.
  bool is_debug_frame_used_;
};

#endif  // _LIBBACKTRACE_BACKTRACE_OFFLINE_H
