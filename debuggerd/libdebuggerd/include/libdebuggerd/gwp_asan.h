/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <log/log.h>
#include <unwindstack/Memory.h>

#include "gwp_asan/common.h"
#include "types.h"
#include "utility.h"

class GwpAsanCrashData {
 public:
  GwpAsanCrashData() = delete;
  ~GwpAsanCrashData() = default;

  // Construct the crash data object. Takes a handle to the object that can
  // supply the memory of the dead process, and pointers to the GWP-ASan state
  // and metadata regions within that process. Also takes the thread information
  // of the crashed process. If the process didn't crash via SEGV, GWP-ASan may
  // still be responsible, as it terminates when it detects an internal error
  // (double free, invalid free). In these cases, we will retrieve the fault
  // address from the GWP-ASan allocator's state.
  GwpAsanCrashData(unwindstack::Memory* process_memory, uintptr_t gwp_asan_state_ptr,
                   uintptr_t gwp_asan_metadata_ptr, const ThreadInfo& thread_info);

  // Is GWP-ASan responsible for this crash.
  bool CrashIsMine() const;

  // Returns the fault address. The fault address may be the same as provided
  // during construction, or it may have been retrieved from GWP-ASan's internal
  // allocator crash state.
  uintptr_t GetFaultAddress() const;

  // Dump the GWP-ASan stringified cause of this crash. May only be called if
  // CrashIsMine() returns true.
  void DumpCause(log_t* log) const;

  // Returns whether this crash has a deallocation trace. May only be called if
  // CrashIsMine() returns true.
  bool HasDeallocationTrace() const;

  // Dump the GWP-ASan deallocation trace for this crash. May only be called if
  // HasDeallocationTrace() returns true.
  void DumpDeallocationTrace(log_t* log, unwindstack::Unwinder* unwinder) const;

  // Returns whether this crash has a allocation trace. May only be called if
  // CrashIsMine() returns true.
  bool HasAllocationTrace() const;

  // Dump the GWP-ASan allocation trace for this crash. May only be called if
  // HasAllocationTrace() returns true.
  void DumpAllocationTrace(log_t* log, unwindstack::Unwinder* unwinder) const;

 protected:
  // Is GWP-ASan responsible for this crash.
  bool is_gwp_asan_responsible_ = false;

  // Thread ID of the crash.
  size_t thread_id_;

  // The type of error that GWP-ASan caused (and the stringified version),
  // Undefined if GWP-ASan isn't responsible for the crash.
  gwp_asan::Error error_;
  const char* error_string_;

  // Pointer to the crash address. Holds the internal crash address if it
  // exists, otherwise the address provided at construction.
  uintptr_t crash_address_ = 0u;

  // Pointer to the metadata for the responsible allocation, nullptr if it
  // doesn't exist.
  const gwp_asan::AllocationMetadata* responsible_allocation_ = nullptr;

  // Internal state.
  gwp_asan::AllocatorState state_;
  std::unique_ptr<const gwp_asan::AllocationMetadata> metadata_;
};
