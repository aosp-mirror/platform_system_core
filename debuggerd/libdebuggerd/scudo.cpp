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

#include <stdint.h>
#include <unistd.h>

#include <vector>

#include "libdebuggerd/scudo.h"
#include "libdebuggerd/tombstone.h"

#include "unwindstack/AndroidUnwinder.h"
#include "unwindstack/Memory.h"

#include <android-base/macros.h>
#include <bionic/macros.h>

#include "tombstone.pb.h"

bool ScudoCrashData::SetErrorInfo(unwindstack::Memory* process_memory,
                                  const ProcessInfo& process_info) {
  if (!process_info.has_fault_address) {
    return false;
  }

  std::vector<char> stack_depot(__scudo_get_stack_depot_size());
  if (!process_memory->ReadFully(process_info.scudo_stack_depot, stack_depot.data(),
                                 stack_depot.size())) {
    return false;
  }
  std::vector<char> region_info(__scudo_get_region_info_size());
  if (!process_memory->ReadFully(process_info.scudo_region_info, region_info.data(),
                                 region_info.size())) {
    return false;
  }
  std::vector<char> ring_buffer(__scudo_get_ring_buffer_size());
  if (!process_memory->ReadFully(process_info.scudo_ring_buffer, ring_buffer.data(),
                                 ring_buffer.size())) {
    return false;
  }

  uintptr_t page_size = getpagesize();

  untagged_fault_addr_ = process_info.untagged_fault_address;
  uintptr_t fault_page = untagged_fault_addr_ & ~(page_size - 1);

  // Attempt to get 16 pages before the fault page and 16 pages after.
  constexpr size_t kExtraPages = 16;
  std::vector<char> memory(page_size * (kExtraPages * 2 + 1));

  // Read faulting page first.
  size_t memory_index = kExtraPages;
  if (!process_memory->ReadFully(fault_page, &memory[memory_index * page_size], page_size)) {
    return false;
  }

  // Attempt to read the pages after the fault page, stop as soon as we
  // fail to read.
  uintptr_t read_addr = fault_page;
  if (!__builtin_add_overflow(fault_page, page_size, &read_addr)) {
    memory_index++;
    for (size_t i = 0; i < kExtraPages; i++, memory_index++) {
      if (!process_memory->ReadFully(read_addr, &memory[memory_index * page_size], page_size)) {
        break;
      }
      if (__builtin_add_overflow(read_addr, page_size, &read_addr)) {
        break;
      }
    }
  }
  uintptr_t memory_end = read_addr;

  // Attempt to read the pages before the fault page, stop as soon as we
  // fail to read.
  memory_index = kExtraPages;
  if (fault_page > 0) {
    read_addr = fault_page - page_size;
    for (size_t i = 0; i < kExtraPages; i++, memory_index--) {
      if (!process_memory->ReadFully(read_addr, &memory[(memory_index - 1) * page_size],
                                     page_size)) {
        break;
      }
      if (read_addr == 0) {
        memory_index--;
        break;
      }
      read_addr -= page_size;
    }
  }
  size_t start_memory_index = memory_index;
  uintptr_t memory_begin = fault_page - (kExtraPages - memory_index) * page_size;

  std::vector<long> memory_tags((memory_end - memory_begin) / kTagGranuleSize);
  read_addr = memory_begin;
  for (size_t i = 0; i < memory_tags.size(); i++) {
    memory_tags[i] = process_memory->ReadTag(read_addr);
    read_addr += kTagGranuleSize;
  }

  __scudo_get_error_info(
      &error_info_, process_info.maybe_tagged_fault_address, stack_depot.data(), region_info.data(),
      ring_buffer.data(), &memory[start_memory_index * page_size],
      reinterpret_cast<const char*>(memory_tags.data()), memory_begin, memory_end - memory_begin);

  return true;
}

bool ScudoCrashData::CrashIsMine() const {
  return error_info_.reports[0].error_type != UNKNOWN;
}

void ScudoCrashData::FillInCause(Cause* cause, const scudo_error_report* report,
                                 unwindstack::AndroidUnwinder* unwinder) const {
  MemoryError* memory_error = cause->mutable_memory_error();
  HeapObject* heap_object = memory_error->mutable_heap();

  memory_error->set_tool(MemoryError_Tool_SCUDO);
  switch (report->error_type) {
    case USE_AFTER_FREE:
      memory_error->set_type(MemoryError_Type_USE_AFTER_FREE);
      break;
    case BUFFER_OVERFLOW:
      memory_error->set_type(MemoryError_Type_BUFFER_OVERFLOW);
      break;
    case BUFFER_UNDERFLOW:
      memory_error->set_type(MemoryError_Type_BUFFER_UNDERFLOW);
      break;
    default:
      memory_error->set_type(MemoryError_Type_UNKNOWN);
      break;
  }

  heap_object->set_address(report->allocation_address);
  heap_object->set_size(report->allocation_size);

  heap_object->set_allocation_tid(report->allocation_tid);
  for (size_t i = 0; i < arraysize(report->allocation_trace) && report->allocation_trace[i]; ++i) {
    unwindstack::FrameData frame_data = unwinder->BuildFrameFromPcOnly(report->allocation_trace[i]);
    BacktraceFrame* f = heap_object->add_allocation_backtrace();
    fill_in_backtrace_frame(f, frame_data);
  }

  heap_object->set_deallocation_tid(report->deallocation_tid);
  for (size_t i = 0; i < arraysize(report->deallocation_trace) && report->deallocation_trace[i];
       ++i) {
    unwindstack::FrameData frame_data =
        unwinder->BuildFrameFromPcOnly(report->deallocation_trace[i]);
    BacktraceFrame* f = heap_object->add_deallocation_backtrace();
    fill_in_backtrace_frame(f, frame_data);
  }

  set_human_readable_cause(cause, untagged_fault_addr_);
}

void ScudoCrashData::AddCauseProtos(Tombstone* tombstone,
                                    unwindstack::AndroidUnwinder* unwinder) const {
  size_t report_num = 0;
  while (report_num < sizeof(error_info_.reports) / sizeof(error_info_.reports[0]) &&
         error_info_.reports[report_num].error_type != UNKNOWN) {
    FillInCause(tombstone->add_causes(), &error_info_.reports[report_num++], unwinder);
  }
}
