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

#include "libdebuggerd/gwp_asan.h"
#include "libdebuggerd/utility.h"

#include "gwp_asan/common.h"
#include "gwp_asan/crash_handler.h"

#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

// Retrieve GWP-ASan state from `state_addr` inside the process at
// `process_memory`. Place the state into `*state`.
static bool retrieve_gwp_asan_state(unwindstack::Memory* process_memory, uintptr_t state_addr,
                                    gwp_asan::AllocatorState* state) {
  return process_memory->ReadFully(state_addr, state, sizeof(*state));
}

// Retrieve the GWP-ASan metadata pool from `metadata_addr` inside the process
// at `process_memory`. The number of metadata slots is retrieved from the
// allocator state provided. This function returns a heap-allocated copy of the
// metadata pool whose ownership should be managed by the caller. Returns
// nullptr on failure.
static const gwp_asan::AllocationMetadata* retrieve_gwp_asan_metadata(
    unwindstack::Memory* process_memory, const gwp_asan::AllocatorState& state,
    uintptr_t metadata_addr) {
  if (state.MaxSimultaneousAllocations > 1024) {
    ALOGE(
        "Error when retrieving GWP-ASan metadata, MSA from state (%zu) "
        "exceeds maximum allowed (1024).",
        state.MaxSimultaneousAllocations);
    return nullptr;
  }

  gwp_asan::AllocationMetadata* meta =
      new gwp_asan::AllocationMetadata[state.MaxSimultaneousAllocations];
  if (!process_memory->ReadFully(metadata_addr, meta,
                                 sizeof(*meta) * state.MaxSimultaneousAllocations)) {
    ALOGE(
        "Error when retrieving GWP-ASan metadata, could not retrieve %zu "
        "pieces of metadata.",
        state.MaxSimultaneousAllocations);
    delete[] meta;
    meta = nullptr;
  }
  return meta;
}

GwpAsanCrashData::GwpAsanCrashData(unwindstack::Memory* process_memory,
                                   const ProcessInfo& process_info, const ThreadInfo& thread_info) {
  if (!process_memory || !process_info.gwp_asan_metadata || !process_info.gwp_asan_state) return;
  // Extract the GWP-ASan regions from the dead process.
  if (!retrieve_gwp_asan_state(process_memory, process_info.gwp_asan_state, &state_)) return;
  metadata_.reset(retrieve_gwp_asan_metadata(process_memory, state_, process_info.gwp_asan_metadata));
  if (!metadata_.get()) return;

  // Get the external crash address from the thread info.
  crash_address_ = 0u;
  if (process_info.has_fault_address) {
    crash_address_ = process_info.untagged_fault_address;
  }

  // Ensure the error belongs to GWP-ASan.
  if (!__gwp_asan_error_is_mine(&state_, crash_address_)) return;

  is_gwp_asan_responsible_ = true;
  thread_id_ = thread_info.tid;

  // Grab the internal error address, if it exists.
  uintptr_t internal_crash_address = __gwp_asan_get_internal_crash_address(&state_);
  if (internal_crash_address) {
    crash_address_ = internal_crash_address;
  }

  // Get other information from the internal state.
  error_ = __gwp_asan_diagnose_error(&state_, metadata_.get(), crash_address_);
  error_string_ = gwp_asan::ErrorToString(error_);
  responsible_allocation_ = __gwp_asan_get_metadata(&state_, metadata_.get(), crash_address_);
}

bool GwpAsanCrashData::CrashIsMine() const {
  return is_gwp_asan_responsible_;
}

void GwpAsanCrashData::DumpCause(log_t* log) const {
  if (!CrashIsMine()) {
    ALOGE("Internal Error: DumpCause() on a non-GWP-ASan crash.");
    return;
  }

  if (error_ == gwp_asan::Error::UNKNOWN) {
    _LOG(log, logtype::HEADER, "Cause: [GWP-ASan]: Unknown error occurred at 0x%" PRIxPTR ".\n",
         crash_address_);
    return;
  }

  if (!responsible_allocation_) {
    _LOG(log, logtype::HEADER, "Cause: [GWP-ASan]: %s at 0x%" PRIxPTR ".\n", error_string_,
         crash_address_);
    return;
  }

  uintptr_t alloc_address = __gwp_asan_get_allocation_address(responsible_allocation_);
  size_t alloc_size = __gwp_asan_get_allocation_size(responsible_allocation_);

  uintptr_t diff;
  const char* location_str;

  if (crash_address_ < alloc_address) {
    // Buffer Underflow, 6 bytes left of a 41-byte allocation at 0xdeadbeef.
    location_str = "left of";
    diff = alloc_address - crash_address_;
  } else if (crash_address_ - alloc_address < alloc_size) {
    // Use After Free, 40 bytes into a 41-byte allocation at 0xdeadbeef.
    location_str = "into";
    diff = crash_address_ - alloc_address;
  } else {
    // Buffer Overflow, 6 bytes right of a 41-byte allocation at 0xdeadbeef, or
    // Invalid Free, 47 bytes right of a 41-byte allocation at 0xdeadbeef.
    location_str = "right of";
    diff = crash_address_ - alloc_address;
    if (error_ == gwp_asan::Error::BUFFER_OVERFLOW) {
      diff -= alloc_size;
    }
  }

  // Suffix of 'bytes', i.e. 4 bytes' vs. '1 byte'.
  const char* byte_suffix = "s";
  if (diff == 1) {
    byte_suffix = "";
  }
  _LOG(log, logtype::HEADER,
       "Cause: [GWP-ASan]: %s, %" PRIuPTR " byte%s %s a %zu-byte allocation at 0x%" PRIxPTR "\n",
       error_string_, diff, byte_suffix, location_str, alloc_size, alloc_address);
}

constexpr size_t kMaxTraceLength = gwp_asan::AllocationMetadata::kMaxTraceLengthToCollect;

bool GwpAsanCrashData::HasDeallocationTrace() const {
  assert(CrashIsMine() && "HasDeallocationTrace(): Crash is not mine!");
  if (!responsible_allocation_ || !__gwp_asan_is_deallocated(responsible_allocation_)) {
    return false;
  }
  return true;
}

void GwpAsanCrashData::DumpDeallocationTrace(log_t* log, unwindstack::Unwinder* unwinder) const {
  assert(HasDeallocationTrace() && "DumpDeallocationTrace(): No dealloc trace!");
  uint64_t thread_id = __gwp_asan_get_deallocation_thread_id(responsible_allocation_);

  std::unique_ptr<uintptr_t> frames(new uintptr_t[kMaxTraceLength]);
  size_t num_frames =
      __gwp_asan_get_deallocation_trace(responsible_allocation_, frames.get(), kMaxTraceLength);

  if (thread_id == gwp_asan::kInvalidThreadID) {
    _LOG(log, logtype::BACKTRACE, "\ndeallocated by thread <unknown>:\n");
  } else {
    _LOG(log, logtype::BACKTRACE, "\ndeallocated by thread %" PRIu64 ":\n", thread_id);
  }

  unwinder->SetDisplayBuildID(true);
  for (size_t i = 0; i < num_frames; ++i) {
    unwindstack::FrameData frame_data = unwinder->BuildFrameFromPcOnly(frames.get()[i]);
    frame_data.num = i;
    _LOG(log, logtype::BACKTRACE, "    %s\n", unwinder->FormatFrame(frame_data).c_str());
  }
}

bool GwpAsanCrashData::HasAllocationTrace() const {
  assert(CrashIsMine() && "HasAllocationTrace(): Crash is not mine!");
  return responsible_allocation_ != nullptr;
}

void GwpAsanCrashData::DumpAllocationTrace(log_t* log, unwindstack::Unwinder* unwinder) const {
  assert(HasAllocationTrace() && "DumpAllocationTrace(): No dealloc trace!");
  uint64_t thread_id = __gwp_asan_get_allocation_thread_id(responsible_allocation_);

  std::unique_ptr<uintptr_t> frames(new uintptr_t[kMaxTraceLength]);
  size_t num_frames =
      __gwp_asan_get_allocation_trace(responsible_allocation_, frames.get(), kMaxTraceLength);

  if (thread_id == gwp_asan::kInvalidThreadID) {
    _LOG(log, logtype::BACKTRACE, "\nallocated by thread <unknown>:\n");
  } else {
    _LOG(log, logtype::BACKTRACE, "\nallocated by thread %" PRIu64 ":\n", thread_id);
  }

  unwinder->SetDisplayBuildID(true);
  for (size_t i = 0; i < num_frames; ++i) {
    unwindstack::FrameData frame_data = unwinder->BuildFrameFromPcOnly(frames.get()[i]);
    frame_data.num = i;
    _LOG(log, logtype::BACKTRACE, "    %s\n", unwinder->FormatFrame(frame_data).c_str());
  }
}
