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
 * Backtracing functions for ARM.
 *
 * This implementation uses the exception unwinding tables provided by
 * the compiler to unwind call frames.  Refer to the ARM Exception Handling ABI
 * documentation (EHABI) for more details about what's going on here.
 *
 * An ELF binary may contain an EXIDX section that provides an index to
 * the exception handling table of each function, sorted by program
 * counter address.
 *
 * When the executable is statically linked, the EXIDX section can be
 * accessed by querying the values of the __exidx_start and __exidx_end
 * symbols.  That said, this library is currently only compiled as
 * a dynamic library, so we will not trouble ourselves with statically
 * linked executables any further.
 *
 * When the Bionic dynamic linker is used, it exports a function called
 * dl_unwind_find_exidx that obtains the EXIDX section for a given
 * absolute program counter address.
 *
 * This implementation also supports unwinding other processes via ptrace().
 * In that case, the EXIDX section is found by reading the ELF section table
 * structures using ptrace().
 *
 * Because the tables are used for exception handling, it can happen that
 * a given function will not have an exception handling table.  In particular,
 * exceptions are assumes to only ever be thrown at call sites.  Therefore,
 * by definition leaf functions will not have exception handling tables.
 * This may make unwinding impossible in some cases although we can still get
 * some idea of the call stack by examining the PC and LR registers.
 *
 * As we are only interested in backtrace information, we do not need
 * to perform all of the work of unwinding such as restoring register
 * state and running cleanup functions.  Unwinding is performed virtually on
 * an abstract machine context consisting of just the ARM core registers.
 * Furthermore, we do not run generic "personality functions" because
 * we may not be in a position to execute arbitrary code, especially if
 * we are running in a signal handler or using ptrace()!
 */

#define LOG_TAG "Corkscrew"
//#define LOG_NDEBUG 0

#include "../backtrace-arch.h"
#include "../backtrace-helper.h"
#include "../ptrace-arch.h"
#include <corkscrew/ptrace.h>

#include <stdlib.h>
#include <signal.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/exec_elf.h>
#include <cutils/log.h>

/* Machine context at the time a signal was raised. */
typedef struct ucontext {
    uint32_t uc_flags;
    struct ucontext* uc_link;
    stack_t uc_stack;
    struct sigcontext {
        uint32_t trap_no;
        uint32_t error_code;
        uint32_t oldmask;
        uint32_t gregs[16];
        uint32_t arm_cpsr;
        uint32_t fault_address;
    } uc_mcontext;
    uint32_t uc_sigmask;
} ucontext_t;

/* Unwind state. */
typedef struct {
    uint32_t gregs[16];
} unwind_state_t;

static const int R_SP = 13;
static const int R_LR = 14;
static const int R_PC = 15;

/* Special EXIDX value that indicates that a frame cannot be unwound. */
static const uint32_t EXIDX_CANTUNWIND = 1;

/* The function exported by the Bionic linker to find the EXIDX
 * table for a given program counter address. */
extern uintptr_t dl_unwind_find_exidx(uintptr_t pc, size_t* out_exidx_size);

/* Transforms a 31-bit place-relative offset to an absolute address.
 * We assume the most significant bit is clear. */
static uintptr_t prel_to_absolute(uintptr_t place, uint32_t prel_offset) {
    return place + (((int32_t)(prel_offset << 1)) >> 1);
}

static uintptr_t get_exception_handler(
        const ptrace_context_t* context, pid_t tid, uintptr_t pc) {
    uintptr_t exidx_start;
    size_t exidx_size;
    if (tid < 0) {
        exidx_start = dl_unwind_find_exidx(pc, &exidx_size);
    } else {
        const map_info_t* mi = find_map_info(context->map_info_list, pc);
        if (mi && mi->data) {
            const map_info_data_t* data = (const map_info_data_t*)mi->data;
            exidx_start = data->exidx_start;
            exidx_size = data->exidx_size;
        } else {
            exidx_start = 0;
            exidx_size = 0;
        }
    }

    // The PC points to the instruction following the branch.
    // We want to find the exception handler entry that corresponds to the branch itself,
    // so we offset the PC backwards into the previous instruction.
    // ARM instructions are 4 bytes, Thumb are 2, so we just subtract two so we either
    // end up in the middle (ARM) or at the beginning of the instruction (Thumb).
    if (pc >= 2) {
        pc -= 2;
    }

    uint32_t handler = 0;
    if (exidx_start) {
        uint32_t low = 0;
        uint32_t high = exidx_size;
        while (low < high) {
            uint32_t index = (low + high) / 2;
            uintptr_t entry = exidx_start + index * 8;
            uint32_t entry_prel_pc;
            if (!try_get_word(tid, entry, &entry_prel_pc)) {
                break;
            }
            uintptr_t entry_pc = prel_to_absolute(entry, entry_prel_pc);
            if (pc < entry_pc) {
                high = index;
                continue;
            }
            if (index + 1 < exidx_size) {
                uintptr_t next_entry = entry + 8;
                uint32_t next_entry_prel_pc;
                if (!try_get_word(tid, next_entry, &next_entry_prel_pc)) {
                    break;
                }
                uintptr_t next_entry_pc = prel_to_absolute(next_entry, next_entry_prel_pc);
                if (pc >= next_entry_pc) {
                    low = index + 1;
                    continue;
                }
            }

            uintptr_t entry_handler_ptr = entry + 4;
            uint32_t entry_handler;
            if (!try_get_word(tid, entry_handler_ptr, &entry_handler)) {
                break;
            }
            if (entry_handler & (1L << 31)) {
                handler = entry_handler_ptr; // in-place handler data
            } else if (entry_handler != EXIDX_CANTUNWIND) {
                handler = prel_to_absolute(entry_handler_ptr, entry_handler);
            }
            break;
        }
    }
    LOGV("get handler: pc=0x%08x, exidx_start=0x%08x, exidx_size=%d, handler=0x%08x",
            pc, exidx_start, exidx_size, handler);
    return handler;
}

typedef struct {
    uintptr_t ptr;
    uint32_t word;
} byte_stream_t;

static bool try_next_byte(pid_t tid, byte_stream_t* stream, uint8_t* out_value) {
    uint8_t result;
    switch (stream->ptr & 3) {
    case 0:
        if (!try_get_word(tid, stream->ptr, &stream->word)) {
            *out_value = 0;
            return false;
        }
        *out_value = stream->word >> 24;
        break;

    case 1:
        *out_value = stream->word >> 16;
        break;

    case 2:
        *out_value = stream->word >> 8;
        break;

    default:
        *out_value = stream->word;
        break;
    }

    LOGV("next_byte: ptr=0x%08x, value=0x%02x", stream->ptr, *out_value);
    stream->ptr += 1;
    return true;
}

static void set_reg(unwind_state_t* state, uint32_t reg, uint32_t value) {
    LOGV("set_reg: reg=%d, value=0x%08x", reg, value);
    state->gregs[reg] = value;
}

static bool try_pop_registers(pid_t tid, unwind_state_t* state, uint32_t mask) {
    uint32_t sp = state->gregs[R_SP];
    bool sp_updated = false;
    for (int i = 0; i < 16; i++) {
        if (mask & (1 << i)) {
            uint32_t value;
            if (!try_get_word(tid, sp, &value)) {
                return false;
            }
            if (i == R_SP) {
                sp_updated = true;
            }
            set_reg(state, i, value);
            sp += 4;
        }
    }
    if (!sp_updated) {
        set_reg(state, R_SP, sp);
    }
    return true;
}

/* Executes a built-in personality routine as defined in the EHABI.
 * Returns true if unwinding should continue.
 *
 * The data for the built-in personality routines consists of a sequence
 * of unwinding instructions, followed by a sequence of scope descriptors,
 * each of which has a length and offset encoded using 16-bit or 32-bit
 * values.
 *
 * We only care about the unwinding instructions.  They specify the
 * operations of an abstract machine whose purpose is to transform the
 * virtual register state (including the stack pointer) such that
 * the call frame is unwound and the PC register points to the call site.
 */
static bool execute_personality_routine(pid_t tid, unwind_state_t* state,
        byte_stream_t* stream, int pr_index) {
    size_t size;
    switch (pr_index) {
    case 0: // Personality routine #0, short frame, descriptors have 16-bit scope.
        size = 3;
        break;
    case 1: // Personality routine #1, long frame, descriptors have 16-bit scope.
    case 2: { // Personality routine #2, long frame, descriptors have 32-bit scope.
        uint8_t size_byte;
        if (!try_next_byte(tid, stream, &size_byte)) {
            return false;
        }
        size = (uint32_t)size_byte * sizeof(uint32_t) + 2;
        break;
    }
    default: // Unknown personality routine.  Stop here.
        return false;
    }

    bool pc_was_set = false;
    while (size--) {
        uint8_t op;
        if (!try_next_byte(tid, stream, &op)) {
            return false;
        }
        if ((op & 0xc0) == 0x00) {
            // "vsp = vsp + (xxxxxx << 2) + 4"
            set_reg(state, R_SP, state->gregs[R_SP] + ((op & 0x3f) << 2) + 4);
        } else if ((op & 0xc0) == 0x40) {
            // "vsp = vsp - (xxxxxx << 2) - 4"
            set_reg(state, R_SP, state->gregs[R_SP] - ((op & 0x3f) << 2) - 4);
        } else if ((op & 0xf0) == 0x80) {
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            uint32_t mask = (((uint32_t)op & 0x0f) << 12) | ((uint32_t)op2 << 4);
            if (mask) {
                // "Pop up to 12 integer registers under masks {r15-r12}, {r11-r4}"
                if (!try_pop_registers(tid, state, mask)) {
                    return false;
                }
                if (mask & (1 << R_PC)) {
                    pc_was_set = true;
                }
            } else {
                // "Refuse to unwind"
                return false;
            }
        } else if ((op & 0xf0) == 0x90) {
            if (op != 0x9d && op != 0x9f) {
                // "Set vsp = r[nnnn]"
                set_reg(state, R_SP, state->gregs[op & 0x0f]);
            } else {
                // "Reserved as prefix for ARM register to register moves"
                // "Reserved as prefix for Intel Wireless MMX register to register moves"
                return false;
            }
        } else if ((op & 0xf8) == 0xa0) {
            // "Pop r4-r[4+nnn]"
            uint32_t mask = (0x0ff0 >> (7 - (op & 0x07))) & 0x0ff0;
            if (!try_pop_registers(tid, state, mask)) {
                return false;
            }
        } else if ((op & 0xf8) == 0xa8) {
            // "Pop r4-r[4+nnn], r14"
            uint32_t mask = ((0x0ff0 >> (7 - (op & 0x07))) & 0x0ff0) | 0x4000;
            if (!try_pop_registers(tid, state, mask)) {
                return false;
            }
        } else if (op == 0xb0) {
            // "Finish"
            break;
        } else if (op == 0xb1) {
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            if (op2 != 0x00 && (op2 & 0xf0) == 0x00) {
                // "Pop integer registers under mask {r3, r2, r1, r0}"
                if (!try_pop_registers(tid, state, op2)) {
                    return false;
                }
            } else {
                // "Spare"
                return false;
            }
        } else if (op == 0xb2) {
            // "vsp = vsp + 0x204 + (uleb128 << 2)"
            uint32_t value = 0;
            uint32_t shift = 0;
            uint8_t op2;
            do {
                if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                    return false;
                }
                value |= (op2 & 0x7f) << shift;
                shift += 7;
            } while (op2 & 0x80);
            set_reg(state, R_SP, state->gregs[R_SP] + (value << 2) + 0x204);
        } else if (op == 0xb3) {
            // "Pop VFP double-precision registers D[ssss]-D[ssss+cccc] saved (as if) by FSTMFDX"
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op2 & 0x0f) * 8 + 12);
        } else if ((op & 0xf8) == 0xb8) {
            // "Pop VFP double-precision registers D[8]-D[8+nnn] saved (as if) by FSTMFDX"
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op & 0x07) * 8 + 12);
        } else if ((op & 0xf8) == 0xc0) {
            // "Intel Wireless MMX pop wR[10]-wR[10+nnn]"
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op & 0x07) * 8 + 8);
        } else if (op == 0xc6) {
            // "Intel Wireless MMX pop wR[ssss]-wR[ssss+cccc]"
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op2 & 0x0f) * 8 + 8);
        } else if (op == 0xc7) {
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            if (op2 != 0x00 && (op2 & 0xf0) == 0x00) {
                // "Intel Wireless MMX pop wCGR registers under mask {wCGR3,2,1,0}"
                set_reg(state, R_SP, state->gregs[R_SP] + __builtin_popcount(op2) * 4);
            } else {
                // "Spare"
                return false;
            }
        } else if (op == 0xc8) {
            // "Pop VFP double precision registers D[16+ssss]-D[16+ssss+cccc]
            // saved (as if) by FSTMFD"
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op2 & 0x0f) * 8 + 8);
        } else if (op == 0xc9) {
            // "Pop VFP double precision registers D[ssss]-D[ssss+cccc] saved (as if) by FSTMFDD"
            uint8_t op2;
            if (!(size--) || !try_next_byte(tid, stream, &op2)) {
                return false;
            }
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op2 & 0x0f) * 8 + 8);
        } else if ((op == 0xf8) == 0xd0) {
            // "Pop VFP double-precision registers D[8]-D[8+nnn] saved (as if) by FSTMFDD"
            set_reg(state, R_SP, state->gregs[R_SP] + (uint32_t)(op & 0x07) * 8 + 8);
        } else {
            // "Spare"
            return false;
        }
    }
    if (!pc_was_set) {
        set_reg(state, R_PC, state->gregs[R_LR]);
    }
    return true;
}

static ssize_t unwind_backtrace_common(pid_t tid, const ptrace_context_t* context,
        unwind_state_t* state, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth) {
    size_t ignored_frames = 0;
    size_t returned_frames = 0;

    uintptr_t handler = get_exception_handler(context, tid, state->gregs[R_PC]);
    if (!handler) {
        // If there is no handler for the PC, the program may have branched to
        // an invalid address.  Check whether we have a handler for the LR
        // where we came from and use that instead.
        backtrace_frame_t* frame = add_backtrace_entry(state->gregs[R_PC], backtrace,
                ignore_depth, max_depth, &ignored_frames, &returned_frames);
        if (frame) {
            frame->stack_top = state->gregs[R_SP];
        }

        handler = get_exception_handler(context, tid, state->gregs[R_LR]);
        if (!handler) {
            // We don't have a handler here either.  Unwinding will not be possible.
            // Return the PC and LR (if it looks sane) and call it good.
            if (state->gregs[R_LR] && state->gregs[R_LR] != state->gregs[R_PC]) {
                // Don't return the SP for this second frame because we don't
                // know how big the first one is so we don't know where this
                // one starts.
                frame = add_backtrace_entry(state->gregs[R_LR], backtrace,
                        ignore_depth, max_depth, &ignored_frames, &returned_frames);
            }
            return returned_frames;
        }

        // Ok, continue from the LR.
        set_reg(state, R_PC, state->gregs[R_LR]);
    }

    while (handler && returned_frames < max_depth) {
        backtrace_frame_t* frame = add_backtrace_entry(state->gregs[R_PC], backtrace,
                ignore_depth, max_depth, &ignored_frames, &returned_frames);
        if (frame) {
            frame->stack_top = state->gregs[R_SP];
        }

        byte_stream_t stream;
        stream.ptr = handler;
        uint8_t pr;
        if (!try_next_byte(tid, &stream, &pr)) {
            break;
        }
        if ((pr & 0xf0) != 0x80) {
            // The first word is a place-relative pointer to a generic personality
            // routine function.  We don't support invoking such functions, so stop here.
            break;
        }

        // The first byte indicates the personality routine to execute.
        // Following bytes provide instructions to the personality routine.
        if (!execute_personality_routine(tid, state, &stream, pr & 0x0f)) {
            break;
        }
        if (frame && state->gregs[R_SP] > frame->stack_top) {
            frame->stack_size = state->gregs[R_SP] - frame->stack_top;
        }

        handler = get_exception_handler(context, tid, state->gregs[R_PC]);
    }
    return returned_frames;
}

ssize_t unwind_backtrace_signal_arch(siginfo_t* siginfo, void* sigcontext,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    const ucontext_t* uc = (const ucontext_t*)sigcontext;

    unwind_state_t state;
    for (int i = 0; i < 16; i++) {
        state.gregs[i] = uc->uc_mcontext.gregs[i];
    }

    return unwind_backtrace_common(-1, NULL, &state, backtrace, ignore_depth, max_depth);
}

ssize_t unwind_backtrace_ptrace_arch(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    struct pt_regs regs;
    if (ptrace(PTRACE_GETREGS, tid, 0, &regs)) {
        return -1;
    }

    unwind_state_t state;
    for (int i = 0; i < 16; i++) {
        state.gregs[i] = regs.uregs[i];
    }

    return unwind_backtrace_common(tid, context, &state, backtrace, ignore_depth, max_depth);
}
