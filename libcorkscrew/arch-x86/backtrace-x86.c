/*
 * Copyright (C) 2011 The Android Open Source Project
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

/*
 * Backtracing functions for x86.
 */

#define LOG_TAG "Corkscrew"
//#define LOG_NDEBUG 0

#include "../backtrace-arch.h"
#include "../backtrace-helper.h"
#include <corkscrew/ptrace.h>

#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <cutils/log.h>

#if defined(__BIONIC__)

#if defined(__BIONIC_HAVE_UCONTEXT_T)

// Bionic offers the Linux kernel headers.
#include <asm/sigcontext.h>
#include <asm/ucontext.h>
typedef struct ucontext ucontext_t;

#else /* __BIONIC_HAVE_UCONTEXT_T */

/* Old versions of the Android <signal.h> didn't define ucontext_t. */

typedef struct {
  uint32_t  gregs[32];
  void*     fpregs;
  uint32_t  oldmask;
  uint32_t  cr2;
} mcontext_t;

enum {
  REG_GS = 0, REG_FS, REG_ES, REG_DS,
  REG_EDI, REG_ESI, REG_EBP, REG_ESP,
  REG_EBX, REG_EDX, REG_ECX, REG_EAX,
  REG_TRAPNO, REG_ERR, REG_EIP, REG_CS,
  REG_EFL, REG_UESP, REG_SS
};

/* Machine context at the time a signal was raised. */
typedef struct ucontext {
    uint32_t uc_flags;
    struct ucontext* uc_link;
    stack_t uc_stack;
    mcontext_t uc_mcontext;
    uint32_t uc_sigmask;
} ucontext_t;

#endif /* __BIONIC_HAVE_UCONTEXT_T */

#else /* __BIONIC__ */

// glibc has its own renaming of the Linux kernel's structures.
#define __USE_GNU // For REG_EBP, REG_ESP, and REG_EIP.
#include <ucontext.h>

#endif /* __ BIONIC__ */

/* Unwind state. */
typedef struct {
    uint32_t ebp;
    uint32_t eip;
    uint32_t esp;
} unwind_state_t;

uintptr_t rewind_pc_arch(const memory_t* memory __attribute__((unused)), uintptr_t pc) {
    // TODO: Implement for x86.
    return pc;
}

static ssize_t unwind_backtrace_common(const memory_t* memory,
        const map_info_t* map_info_list __attribute__((unused)),
        unwind_state_t* state, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth) {
    size_t ignored_frames = 0;
    size_t returned_frames = 0;

    for (size_t index = 0; state->ebp && returned_frames < max_depth; index++) {
        backtrace_frame_t* frame = add_backtrace_entry(
                index ? rewind_pc_arch(memory, state->eip) : state->eip,
                backtrace, ignore_depth, max_depth,
                &ignored_frames, &returned_frames);
        uint32_t next_esp = state->ebp + 8;
        if (frame) {
            frame->stack_top = state->esp;
            if (state->esp < next_esp) {
                frame->stack_size = next_esp - state->esp;
            }
        }
        state->esp = next_esp;
        if (!try_get_word(memory, state->ebp + 4, &state->eip)
                || !try_get_word(memory, state->ebp, &state->ebp)
                || !state->eip) {
            break;
        }
    }

    return returned_frames;
}

ssize_t unwind_backtrace_signal_arch(siginfo_t* siginfo __attribute__((unused)), void* sigcontext,
        const map_info_t* map_info_list,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    const ucontext_t* uc = (const ucontext_t*)sigcontext;

    unwind_state_t state;
    state.ebp = uc->uc_mcontext.gregs[REG_EBP];
    state.esp = uc->uc_mcontext.gregs[REG_ESP];
    state.eip = uc->uc_mcontext.gregs[REG_EIP];

    memory_t memory;
    init_memory(&memory, map_info_list);
    return unwind_backtrace_common(&memory, map_info_list,
            &state, backtrace, ignore_depth, max_depth);
}

ssize_t unwind_backtrace_ptrace_arch(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    pt_regs_x86_t regs;
    if (ptrace(PTRACE_GETREGS, tid, 0, &regs)) {
        return -1;
    }

    unwind_state_t state;
    state.ebp = regs.ebp;
    state.eip = regs.eip;
    state.esp = regs.esp;

    memory_t memory;
    init_memory_ptrace(&memory, tid);
    return unwind_backtrace_common(&memory, context->map_info_list,
            &state, backtrace, ignore_depth, max_depth);
}
