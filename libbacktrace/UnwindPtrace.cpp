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

#include <sys/types.h>
#include <string.h>

#include <cutils/log.h>

#include <libunwind.h>
#include <libunwind-ptrace.h>

#include "UnwindPtrace.h"

UnwindPtrace::UnwindPtrace() : addr_space_(NULL), upt_info_(NULL) {
}

UnwindPtrace::~UnwindPtrace() {
  if (upt_info_) {
    _UPT_destroy(upt_info_);
    upt_info_ = NULL;
  }
  if (addr_space_) {
    unw_destroy_addr_space(addr_space_);
    addr_space_ = NULL;
  }
}

bool UnwindPtrace::Unwind(size_t num_ignore_frames) {
  addr_space_ = unw_create_addr_space(&_UPT_accessors, 0);
  if (!addr_space_) {
    BACK_LOGW("unw_create_addr_space failed.");
    return false;
  }

  upt_info_ = reinterpret_cast<struct UPT_info*>(_UPT_create(backtrace_obj_->Tid()));
  if (!upt_info_) {
    BACK_LOGW("Failed to create upt info.");
    return false;
  }

  backtrace_t* backtrace = GetBacktraceData();
  backtrace->num_frames = 0;

  unw_cursor_t cursor;
  int ret = unw_init_remote(&cursor, addr_space_, upt_info_);
  if (ret < 0) {
    BACK_LOGW("unw_init_remote failed %d", ret);
    return false;
  }

  do {
    unw_word_t pc;
    ret = unw_get_reg(&cursor, UNW_REG_IP, &pc);
    if (ret < 0) {
      BACK_LOGW("Failed to read IP %d", ret);
      break;
    }
    unw_word_t sp;
    ret = unw_get_reg(&cursor, UNW_REG_SP, &sp);
    if (ret < 0) {
      BACK_LOGW("Failed to read SP %d", ret);
      break;
    }

    if (num_ignore_frames == 0) {
      size_t num_frames = backtrace->num_frames;
      backtrace_frame_data_t* frame = &backtrace->frames[num_frames];
      frame->pc = static_cast<uintptr_t>(pc);
      frame->sp = static_cast<uintptr_t>(sp);
      frame->stack_size = 0;
      frame->map_name = NULL;
      frame->map_offset = 0;
      frame->func_name = NULL;
      frame->func_offset = 0;

      if (num_frames > 0) {
        backtrace_frame_data_t* prev = &backtrace->frames[num_frames-1];
        prev->stack_size = frame->sp - prev->sp;
      }

      std::string func_name = backtrace_obj_->GetFunctionName(frame->pc, &frame->func_offset);
      if (!func_name.empty()) {
        frame->func_name = strdup(func_name.c_str());
      }

      uintptr_t map_start;
      frame->map_name = backtrace_obj_->GetMapName(frame->pc, &map_start);
      if (frame->map_name) {
        frame->map_offset = frame->pc - map_start;
      }

      backtrace->num_frames++;
    } else {
      num_ignore_frames--;
    }
    ret = unw_step (&cursor);
  } while (ret > 0 && backtrace->num_frames < MAX_BACKTRACE_FRAMES);

  return true;
}

std::string UnwindPtrace::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  *offset = 0;
  char buf[512];
  unw_word_t value;
  if (unw_get_proc_name_by_ip(addr_space_, pc, buf, sizeof(buf), &value,
                              upt_info_) >= 0 && buf[0] != '\0') {
    *offset = static_cast<uintptr_t>(value);
    return buf;
  }
  return "";
}

//-------------------------------------------------------------------------
// C++ object creation function.
//-------------------------------------------------------------------------
Backtrace* CreatePtraceObj(pid_t pid, pid_t tid) {
  return new BacktracePtrace(new UnwindPtrace(), pid, tid);
}
