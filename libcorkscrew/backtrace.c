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

#define LOG_TAG "Corkscrew"
//#define LOG_NDEBUG 0

#include "backtrace-arch.h"
#include "backtrace-helper.h"
#include "ptrace-arch.h"
#include <corkscrew/map_info.h>
#include <corkscrew/symbol_table.h>
#include <corkscrew/ptrace.h>
#include <corkscrew/demangle.h>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <unwind.h>
#include <sys/exec_elf.h>
#include <cutils/log.h>

#if HAVE_DLADDR
#include <dlfcn.h>
#endif

typedef struct {
    backtrace_frame_t* backtrace;
    size_t ignore_depth;
    size_t max_depth;
    size_t ignored_frames;
    size_t returned_frames;
} backtrace_state_t;

static _Unwind_Reason_Code unwind_backtrace_callback(struct _Unwind_Context* context, void* arg) {
    backtrace_state_t* state = (backtrace_state_t*)arg;
    uintptr_t pc = _Unwind_GetIP(context);
    if (pc) {
        // TODO: Get information about the stack layout from the _Unwind_Context.
        //       This will require a new architecture-specific function to query
        //       the appropriate registers.  Current callers of unwind_backtrace
        //       don't need this information, so we won't bother collecting it just yet.
        add_backtrace_entry(pc, state->backtrace,
                state->ignore_depth, state->max_depth,
                &state->ignored_frames, &state->returned_frames);
    }
    return state->returned_frames < state->max_depth ? _URC_NO_REASON : _URC_END_OF_STACK;
}

ssize_t unwind_backtrace(backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
    backtrace_state_t state;
    state.backtrace = backtrace;
    state.ignore_depth = ignore_depth;
    state.max_depth = max_depth;
    state.ignored_frames = 0;
    state.returned_frames = 0;

    _Unwind_Reason_Code rc =_Unwind_Backtrace(unwind_backtrace_callback, &state);
    if (state.returned_frames) {
        return state.returned_frames;
    }
    return rc == _URC_END_OF_STACK ? 0 : -1;
}

#ifdef CORKSCREW_HAVE_ARCH
static pthread_mutex_t g_unwind_signal_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile struct {
    backtrace_frame_t* backtrace;
    size_t ignore_depth;
    size_t max_depth;
    size_t returned_frames;
    bool done;
} g_unwind_signal_state;

static void unwind_backtrace_thread_signal_handler(int n, siginfo_t* siginfo, void* sigcontext) {
    backtrace_frame_t* backtrace = g_unwind_signal_state.backtrace;
    if (backtrace) {
        g_unwind_signal_state.backtrace = NULL;
        g_unwind_signal_state.returned_frames = unwind_backtrace_signal_arch(
                siginfo, sigcontext, backtrace,
                g_unwind_signal_state.ignore_depth,
                g_unwind_signal_state.max_depth);
        g_unwind_signal_state.done = true;
    }
}
#endif

ssize_t unwind_backtrace_thread(pid_t tid, backtrace_frame_t* backtrace,
        size_t ignore_depth, size_t max_depth) {
#ifdef CORKSCREW_HAVE_ARCH
    struct sigaction act;
    struct sigaction oact;
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = unwind_backtrace_thread_signal_handler;
    act.sa_flags = SA_RESTART | SA_SIGINFO;
    sigemptyset(&act.sa_mask);

    pthread_mutex_lock(&g_unwind_signal_mutex);

    g_unwind_signal_state.backtrace = backtrace;
    g_unwind_signal_state.ignore_depth = ignore_depth;
    g_unwind_signal_state.max_depth = max_depth;
    g_unwind_signal_state.returned_frames = 0;
    g_unwind_signal_state.done = false;

    ssize_t frames = -1;
    if (!sigaction(SIGURG, &act, &oact)) {
        if (!kill(tid, SIGURG)) {
            while (!g_unwind_signal_state.done) {
                usleep(1000);
            }
            frames = g_unwind_signal_state.returned_frames;
        }
        sigaction(SIGURG, &oact, NULL);
    }

    g_unwind_signal_state.backtrace = NULL;

    pthread_mutex_unlock(&g_unwind_signal_mutex);
    return frames;
#else
    return -1;
#endif
}

ssize_t unwind_backtrace_ptrace(pid_t tid, const ptrace_context_t* context,
        backtrace_frame_t* backtrace, size_t ignore_depth, size_t max_depth) {
#ifdef CORKSCREW_HAVE_ARCH
    return unwind_backtrace_ptrace_arch(tid, context, backtrace, ignore_depth, max_depth);
#else
    return -1;
#endif
}

static void init_backtrace_symbol(backtrace_symbol_t* symbol, uintptr_t pc) {
    symbol->relative_pc = pc;
    symbol->map_info = NULL;
    symbol->name = NULL;
    symbol->demangled_name = NULL;
}

void get_backtrace_symbols(const backtrace_frame_t* backtrace, size_t frames,
        backtrace_symbol_t* backtrace_symbols) {
    const map_info_t* milist = my_map_info_list();
    for (size_t i = 0; i < frames; i++) {
        const backtrace_frame_t* frame = &backtrace[i];
        backtrace_symbol_t* symbol = &backtrace_symbols[i];
        init_backtrace_symbol(symbol, frame->absolute_pc);

        const map_info_t* mi = find_map_info(milist, frame->absolute_pc);
        if (mi) {
            symbol->relative_pc = frame->absolute_pc - mi->start;
            symbol->map_info = mi;
#if HAVE_DLADDR
            Dl_info info;
            if (dladdr((const void*)frame->absolute_pc, &info) && info.dli_sname) {
                symbol->name = info.dli_sname;
                symbol->demangled_name = demangle_symbol_name(symbol->name);
            }
#endif
        }
    }
}

void get_backtrace_symbols_ptrace(const ptrace_context_t* context,
        const backtrace_frame_t* backtrace, size_t frames,
        backtrace_symbol_t* backtrace_symbols) {
    for (size_t i = 0; i < frames; i++) {
        const backtrace_frame_t* frame = &backtrace[i];
        backtrace_symbol_t* symbol = &backtrace_symbols[i];
        init_backtrace_symbol(symbol, frame->absolute_pc);

        const map_info_t* mi;
        const symbol_t* s;
        find_symbol_ptrace(context, frame->absolute_pc, &mi, &s);
        if (mi) {
            symbol->relative_pc = frame->absolute_pc - mi->start;
            symbol->map_info = mi;
        }
        if (s) {
            symbol->name = s->name;
            symbol->demangled_name = demangle_symbol_name(symbol->name);
        }
    }
}

void free_backtrace_symbols(backtrace_symbol_t* backtrace_symbols, size_t frames) {
    for (size_t i = 0; i < frames; i++) {
        backtrace_symbol_t* symbol = &backtrace_symbols[i];
        free(symbol->demangled_name);
        init_backtrace_symbol(symbol, 0);
    }
}
