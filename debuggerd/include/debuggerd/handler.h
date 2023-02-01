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

#include <bionic/reserved_signals.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/system_properties.h>
#include <sys/types.h>

__BEGIN_DECLS

// Forward declare these classes so not everyone has to include GWP-ASan
// headers.
namespace gwp_asan {
struct AllocatorState;
struct AllocationMetadata;
};  // namespace gwp_asan

// When updating this data structure, CrashInfoDataDynamic and the code in
// ReadCrashInfo() must also be updated.
struct debugger_process_info {
  void* abort_msg;
  void* fdsan_table;
  const gwp_asan::AllocatorState* gwp_asan_state;
  const gwp_asan::AllocationMetadata* gwp_asan_metadata;
  const char* scudo_stack_depot;
  const char* scudo_region_info;
  const char* scudo_ring_buffer;
  size_t scudo_ring_buffer_size;
};

// These callbacks are called in a signal handler, and thus must be async signal safe.
// If null, the callbacks will not be called.
typedef struct {
  debugger_process_info (*get_process_info)();
  void (*post_dump)();
} debuggerd_callbacks_t;

void debuggerd_init(debuggerd_callbacks_t* callbacks);

// DEBUGGER_ACTION_DUMP_TOMBSTONE and DEBUGGER_ACTION_DUMP_BACKTRACE are both
// triggered via BIONIC_SIGNAL_DEBUGGER. The debugger_action_t is sent via si_value
// using sigqueue(2) or equivalent. If no si_value is specified (e.g. if the
// signal is sent by kill(2)), the default behavior is to print the backtrace
// to the log.
#define DEBUGGER_SIGNAL BIONIC_SIGNAL_DEBUGGER

static void __attribute__((__unused__)) debuggerd_register_handlers(struct sigaction* action) {
  bool enabled = true;
#if ANDROID_DEBUGGABLE
  char value[PROP_VALUE_MAX] = "";
  enabled = !(__system_property_get("debug.debuggerd.disable", value) > 0 && !strcmp(value, "1"));
#endif
  if (enabled) {
    sigaction(SIGABRT, action, nullptr);
    sigaction(SIGBUS, action, nullptr);
    sigaction(SIGFPE, action, nullptr);
    sigaction(SIGILL, action, nullptr);
    sigaction(SIGSEGV, action, nullptr);
    sigaction(SIGSTKFLT, action, nullptr);
    sigaction(SIGSYS, action, nullptr);
    sigaction(SIGTRAP, action, nullptr);
  }

  sigaction(BIONIC_SIGNAL_DEBUGGER, action, nullptr);
}

__END_DECLS
