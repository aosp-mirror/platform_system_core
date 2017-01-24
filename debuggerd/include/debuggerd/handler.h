/*
 * Copyright 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <signal.h>
#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

__BEGIN_DECLS

// These callbacks are called in a signal handler, and thus must be async signal safe.
// If null, the callbacks will not be called.
typedef struct {
  struct abort_msg_t* (*get_abort_message)();
  void (*post_dump)();
} debuggerd_callbacks_t;

void debuggerd_init(debuggerd_callbacks_t* callbacks);

// DEBUGGER_ACTION_DUMP_TOMBSTONE and DEBUGGER_ACTION_DUMP_BACKTRACE are both
// triggered via DEBUGGER_SIGNAL. The debugger_action_t is sent via si_value
// using sigqueue(2) or equivalent. If no si_value is specified (e.g. if the
// signal is sent by kill(2)), the default behavior is to print the backtrace
// to the log.
#define DEBUGGER_SIGNAL (__SIGRTMIN + 3)

static void __attribute__((__unused__)) debuggerd_register_handlers(struct sigaction* action) {
  sigaction(SIGABRT, action, nullptr);
  sigaction(SIGBUS, action, nullptr);
  sigaction(SIGFPE, action, nullptr);
  sigaction(SIGILL, action, nullptr);
  sigaction(SIGSEGV, action, nullptr);
#if defined(SIGSTKFLT)
  sigaction(SIGSTKFLT, action, nullptr);
#endif
  sigaction(SIGSYS, action, nullptr);
  sigaction(SIGTRAP, action, nullptr);
  sigaction(DEBUGGER_SIGNAL, action, nullptr);
}

__END_DECLS
