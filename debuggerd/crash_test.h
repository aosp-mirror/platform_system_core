/*
 * Copyright 2021, The Android Open Source Project
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

// Only support V1 of these structures.
// See https://sourceware.org/gdb/onlinedocs/gdb/JIT-Interface.html
// for information on the JIT Compilation Interface.
// Also, see libunwindstack/GlobalDebugImpl.h for the full definition of
// these structures.
struct JITCodeEntry {
  uintptr_t next;
  uintptr_t prev;
  uintptr_t symfile_addr;
  uint64_t symfile_size;
};

struct JITDescriptor {
  uint32_t version;
  uint32_t action_flag;
  uintptr_t relevant_entry;
  uintptr_t first_entry;
};
