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
#include "libdebuggerd/tombstone.h"
#include "libdebuggerd/utility.h"

#include "gwp_asan/common.h"
#include "gwp_asan/crash_handler.h"

#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

#include "tombstone.pb.h"

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
  // 1 million GWP-ASan slots would take 4.1GiB of space. Thankfully, copying
  // the metadata for that amount of slots is only 532MiB, and this really will
  // only be used with some ridiculous torture-tests.
  if (state.MaxSimultaneousAllocations > 1000000) {
    ALOGE(
        "Error when retrieving GWP-ASan metadata, MSA from state (%zu) "
        "exceeds maximum allowed (1,000,000).",
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

constexpr size_t kMaxTraceLength = gwp_asan::AllocationMetadata::kMaxTraceLengthToCollect;

void GwpAsanCrashData::AddCauseProtos(Tombstone* tombstone, unwindstack::Unwinder* unwinder) const {
  if (!CrashIsMine()) {
    ALOGE("Internal Error: AddCauseProtos() on a non-GWP-ASan crash.");
    return;
  }

  Cause* cause = tombstone->add_causes();
  MemoryError* memory_error = cause->mutable_memory_error();
  HeapObject* heap_object = memory_error->mutable_heap();

  memory_error->set_tool(MemoryError_Tool_GWP_ASAN);
  switch (error_) {
    case gwp_asan::Error::USE_AFTER_FREE:
      memory_error->set_type(MemoryError_Type_USE_AFTER_FREE);
      break;
    case gwp_asan::Error::DOUBLE_FREE:
      memory_error->set_type(MemoryError_Type_DOUBLE_FREE);
      break;
    case gwp_asan::Error::INVALID_FREE:
      memory_error->set_type(MemoryError_Type_INVALID_FREE);
      break;
    case gwp_asan::Error::BUFFER_OVERFLOW:
      memory_error->set_type(MemoryError_Type_BUFFER_OVERFLOW);
      break;
    case gwp_asan::Error::BUFFER_UNDERFLOW:
      memory_error->set_type(MemoryError_Type_BUFFER_UNDERFLOW);
      break;
    default:
      memory_error->set_type(MemoryError_Type_UNKNOWN);
      break;
  }

  heap_object->set_address(__gwp_asan_get_allocation_address(responsible_allocation_));
  heap_object->set_size(__gwp_asan_get_allocation_size(responsible_allocation_));
  unwinder->SetDisplayBuildID(true);

  std::unique_ptr<uintptr_t[]> frames(new uintptr_t[kMaxTraceLength]);

  heap_object->set_allocation_tid(__gwp_asan_get_allocation_thread_id(responsible_allocation_));
  size_t num_frames =
      __gwp_asan_get_allocation_trace(responsible_allocation_, frames.get(), kMaxTraceLength);
  for (size_t i = 0; i != num_frames; ++i) {
    unwindstack::FrameData frame_data = unwinder->BuildFrameFromPcOnly(frames[i]);
    BacktraceFrame* f = heap_object->add_allocation_backtrace();
    fill_in_backtrace_frame(f, frame_data);
  }

  heap_object->set_deallocation_tid(__gwp_asan_get_deallocation_thread_id(responsible_allocation_));
  num_frames =
      __gwp_asan_get_deallocation_trace(responsible_allocation_, frames.get(), kMaxTraceLength);
  for (size_t i = 0; i != num_frames; ++i) {
    unwindstack::FrameData frame_data = unwinder->BuildFrameFromPcOnly(frames[i]);
    BacktraceFrame* f = heap_object->add_deallocation_backtrace();
    fill_in_backtrace_frame(f, frame_data);
  }

  set_human_readable_cause(cause, crash_address_);
}
