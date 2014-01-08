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

#include <sys/types.h>

#include <cutils/log.h>

#include <backtrace/backtrace.h>

#define UNW_LOCAL_ONLY
#include <libunwind.h>

#include "UnwindCurrent.h"

// Define the ucontext_t structures needed for each supported arch.
#if defined(__arm__)
  // The current version of the <signal.h> doesn't define ucontext_t.
  #include <asm/sigcontext.h> // Ensure 'struct sigcontext' is defined.

  // Machine context at the time a signal was raised.
  typedef struct ucontext {
    uint32_t uc_flags;
    struct ucontext* uc_link;
    stack_t uc_stack;
    struct sigcontext uc_mcontext;
    uint32_t uc_sigmask;
  } ucontext_t;
#elif defined(__i386__)
  #include <asm/sigcontext.h>
  #include <asm/ucontext.h>
  typedef struct ucontext ucontext_t;
#elif !defined(__mips__)
  #error Unsupported architecture.
#endif

//-------------------------------------------------------------------------
// UnwindCurrent functions.
//-------------------------------------------------------------------------
UnwindCurrent::UnwindCurrent() {
}

UnwindCurrent::~UnwindCurrent() {
}

bool UnwindCurrent::Unwind(size_t num_ignore_frames) {
  int ret = unw_getcontext(&context_);
  if (ret < 0) {
    BACK_LOGW("unw_getcontext failed %d", ret);
    return false;
  }
  return UnwindFromContext(num_ignore_frames, true);
}

std::string UnwindCurrent::GetFunctionNameRaw(uintptr_t pc, uintptr_t* offset) {
  *offset = 0;
  char buf[512];
  unw_word_t value;
  if (unw_get_proc_name_by_ip(unw_local_addr_space, pc, buf, sizeof(buf),
                              &value, &context_) >= 0 && buf[0] != '\0') {
    *offset = static_cast<uintptr_t>(value);
    return buf;
  }
  return "";
}

bool UnwindCurrent::UnwindFromContext(size_t num_ignore_frames, bool resolve) {
  backtrace_t* backtrace = GetBacktraceData();
  backtrace->num_frames = 0;

  // The cursor structure is pretty large, do not put it on the stack.
  unw_cursor_t* cursor = new unw_cursor_t;
  int ret = unw_init_local(cursor, &context_);
  if (ret < 0) {
    BACK_LOGW("unw_init_local failed %d", ret);
    delete cursor;
    return false;
  }

  do {
    unw_word_t pc;
    ret = unw_get_reg(cursor, UNW_REG_IP, &pc);
    if (ret < 0) {
      BACK_LOGW("Failed to read IP %d", ret);
      break;
    }
    unw_word_t sp;
    ret = unw_get_reg(cursor, UNW_REG_SP, &sp);
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
        // Set the stack size for the previous frame.
        backtrace_frame_data_t* prev = &backtrace->frames[num_frames-1];
        prev->stack_size = frame->sp - prev->sp;
      }

      if (resolve) {
        std::string func_name = backtrace_obj_->GetFunctionName(frame->pc, &frame->func_offset);
        if (!func_name.empty()) {
          frame->func_name = strdup(func_name.c_str());
        }

        uintptr_t map_start;
        frame->map_name = backtrace_obj_->GetMapName(frame->pc, &map_start);
        if (frame->map_name) {
          frame->map_offset = frame->pc - map_start;
        }
      }

      backtrace->num_frames++;
    } else {
      num_ignore_frames--;
    }
    ret = unw_step (cursor);
  } while (ret > 0 && backtrace->num_frames < MAX_BACKTRACE_FRAMES);

  delete cursor;
  return true;
}

void UnwindCurrent::ExtractContext(void* sigcontext) {
  unw_tdep_context_t* context = reinterpret_cast<unw_tdep_context_t*>(&context_);
  const ucontext_t* uc = reinterpret_cast<const ucontext_t*>(sigcontext);

#if defined(__arm__)
  context->regs[0] = uc->uc_mcontext.arm_r0;
  context->regs[1] = uc->uc_mcontext.arm_r1;
  context->regs[2] = uc->uc_mcontext.arm_r2;
  context->regs[3] = uc->uc_mcontext.arm_r3;
  context->regs[4] = uc->uc_mcontext.arm_r4;
  context->regs[5] = uc->uc_mcontext.arm_r5;
  context->regs[6] = uc->uc_mcontext.arm_r6;
  context->regs[7] = uc->uc_mcontext.arm_r7;
  context->regs[8] = uc->uc_mcontext.arm_r8;
  context->regs[9] = uc->uc_mcontext.arm_r9;
  context->regs[10] = uc->uc_mcontext.arm_r10;
  context->regs[11] = uc->uc_mcontext.arm_fp;
  context->regs[12] = uc->uc_mcontext.arm_ip;
  context->regs[13] = uc->uc_mcontext.arm_sp;
  context->regs[14] = uc->uc_mcontext.arm_lr;
  context->regs[15] = uc->uc_mcontext.arm_pc;
#elif defined(__mips__) || defined(__i386__)
  context->uc_mcontext = uc->uc_mcontext;
#endif
}

//-------------------------------------------------------------------------
// UnwindThread functions.
//-------------------------------------------------------------------------
UnwindThread::UnwindThread() {
}

UnwindThread::~UnwindThread() {
}

bool UnwindThread::Init() {
  return true;
}

void UnwindThread::ThreadUnwind(
    siginfo_t* /*siginfo*/, void* sigcontext, size_t num_ignore_frames) {
  ExtractContext(sigcontext);
  UnwindFromContext(num_ignore_frames, false);
}

//-------------------------------------------------------------------------
// C++ object creation function.
//-------------------------------------------------------------------------
Backtrace* CreateCurrentObj(backtrace_map_info_t* map_info) {
  return new BacktraceCurrent(new UnwindCurrent(), map_info);
}

Backtrace* CreateThreadObj(pid_t tid, backtrace_map_info_t* map_info) {
  UnwindThread* thread_obj = new UnwindThread();
  return new BacktraceThread(thread_obj, thread_obj, tid, map_info);
}
