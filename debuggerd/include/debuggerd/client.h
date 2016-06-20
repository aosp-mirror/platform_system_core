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

#include <stdint.h>
#include <sys/cdefs.h>
#include <sys/types.h>

// On 32-bit devices, DEBUGGER_SOCKET_NAME is a 32-bit debuggerd.
// On 64-bit devices, DEBUGGER_SOCKET_NAME is a 64-bit debuggerd.
#define DEBUGGER_SOCKET_NAME "android:debuggerd"

// Used only on 64-bit devices for debuggerd32.
#define DEBUGGER32_SOCKET_NAME "android:debuggerd32"

__BEGIN_DECLS

typedef enum {
  // dump a crash
  DEBUGGER_ACTION_CRASH,
  // dump a tombstone file
  DEBUGGER_ACTION_DUMP_TOMBSTONE,
  // dump a backtrace only back to the socket
  DEBUGGER_ACTION_DUMP_BACKTRACE,
} debugger_action_t;

// Make sure that all values have a fixed size so that this structure
// is the same for 32 bit and 64 bit processes.
typedef struct __attribute__((packed)) {
  int32_t action;
  pid_t tid;
  uint64_t abort_msg_address;
  int32_t original_si_code;
} debugger_msg_t;

// These callbacks are called in a signal handler, and thus must be async signal safe.
// If null, the callbacks will not be called.
typedef struct {
  struct abort_msg_t* (*get_abort_message)();
  void (*post_dump)();
} debuggerd_callbacks_t;

void debuggerd_init(debuggerd_callbacks_t* callbacks);

__END_DECLS
