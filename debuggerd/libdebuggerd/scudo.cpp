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

#include "libdebuggerd/scudo.h"
#include "libdebuggerd/gwp_asan.h"

#include "unwindstack/Memory.h"
#include "unwindstack/Unwinder.h"

#include <bionic/macros.h>

std::unique_ptr<char[]> AllocAndReadFully(unwindstack::Memory* process_memory, uint64_t addr,
                                          size_t size) {
  auto buf = std::make_unique<char[]>(size);
  if (!process_memory->ReadFully(addr, buf.get(), size)) {
    return std::unique_ptr<char[]>();
  }
  return buf;
}

static const uintptr_t kTagGranuleSize = 16;

ScudoCrashData::ScudoCrashData(unwindstack::Memory* process_memory,
                               const ProcessInfo& process_info) {
  if (!process_info.has_fault_address) {
    return;
  }

  auto stack_depot = AllocAndReadFully(process_memory, process_info.scudo_stack_depot,
                                       __scudo_get_stack_depot_size());
  auto region_info = AllocAndReadFully(process_memory, process_info.scudo_region_info,
                                       __scudo_get_region_info_size());
  auto ring_buffer = AllocAndReadFully(process_memory, process_info.scudo_ring_buffer,
                                       __scudo_get_ring_buffer_size());

  untagged_fault_addr_ = process_info.untagged_fault_address;
  uintptr_t fault_page = untagged_fault_addr_ & ~(PAGE_SIZE - 1);

  uintptr_t memory_begin = fault_page - PAGE_SIZE * 16;
  if (memory_begin > fault_page) {
    return;
  }

  uintptr_t memory_end = fault_page + PAGE_SIZE * 16;
  if (memory_end < fault_page) {
    return;
  }

  auto memory = std::make_unique<char[]>(memory_end - memory_begin);
  for (auto i = memory_begin; i != memory_end; i += PAGE_SIZE) {
    process_memory->ReadFully(i, memory.get() + i - memory_begin, PAGE_SIZE);
  }

  auto memory_tags = std::make_unique<char[]>((memory_end - memory_begin) / kTagGranuleSize);
  for (auto i = memory_begin; i != memory_end; i += kTagGranuleSize) {
    memory_tags[(i - memory_begin) / kTagGranuleSize] = process_memory->ReadTag(i);
  }

  __scudo_get_error_info(&error_info_, process_info.maybe_tagged_fault_address, stack_depot.get(),
                         region_info.get(), ring_buffer.get(), memory.get(), memory_tags.get(),
                         memory_begin, memory_end - memory_begin);
}

bool ScudoCrashData::CrashIsMine() const {
  return error_info_.reports[0].error_type != UNKNOWN;
}

void ScudoCrashData::DumpCause(log_t* log, unwindstack::Unwinder* unwinder) const {
  if (error_info_.reports[1].error_type != UNKNOWN) {
    _LOG(log, logtype::HEADER,
         "\nNote: multiple potential causes for this crash were detected, listing them in "
         "decreasing order of probability.\n");
  }

  size_t report_num = 0;
  while (report_num < sizeof(error_info_.reports) / sizeof(error_info_.reports[0]) &&
         error_info_.reports[report_num].error_type != UNKNOWN) {
    DumpReport(&error_info_.reports[report_num++], log, unwinder);
  }
}

void ScudoCrashData::DumpReport(const scudo_error_report* report, log_t* log,
                                unwindstack::Unwinder* unwinder) const {
  const char *error_type_str;
  switch (report->error_type) {
    case USE_AFTER_FREE:
      error_type_str = "Use After Free";
      break;
    case BUFFER_OVERFLOW:
      error_type_str = "Buffer Overflow";
      break;
    case BUFFER_UNDERFLOW:
      error_type_str = "Buffer Underflow";
      break;
    default:
      error_type_str = "Unknown";
      break;
  }

  uintptr_t diff;
  const char* location_str;

  if (untagged_fault_addr_ < report->allocation_address) {
    // Buffer Underflow, 6 bytes left of a 41-byte allocation at 0xdeadbeef.
    location_str = "left of";
    diff = report->allocation_address - untagged_fault_addr_;
  } else if (untagged_fault_addr_ - report->allocation_address < report->allocation_size) {
    // Use After Free, 40 bytes into a 41-byte allocation at 0xdeadbeef.
    location_str = "into";
    diff = untagged_fault_addr_ - report->allocation_address;
  } else {
    // Buffer Overflow, 6 bytes right of a 41-byte allocation at 0xdeadbeef.
    location_str = "right of";
    diff = untagged_fault_addr_ - report->allocation_address - report->allocation_size;
  }

  // Suffix of 'bytes', i.e. 4 bytes' vs. '1 byte'.
  const char* byte_suffix = "s";
  if (diff == 1) {
    byte_suffix = "";
  }
  _LOG(log, logtype::HEADER,
       "\nCause: [MTE]: %s, %" PRIuPTR " byte%s %s a %zu-byte allocation at 0x%" PRIxPTR "\n",
       error_type_str, diff, byte_suffix, location_str, report->allocation_size,
       report->allocation_address);

  if (report->allocation_trace[0]) {
    _LOG(log, logtype::BACKTRACE, "\nallocated by thread %u:\n", report->allocation_tid);
    unwinder->SetDisplayBuildID(true);
    for (size_t i = 0; i < 64 && report->allocation_trace[i]; ++i) {
      unwindstack::FrameData frame_data =
          unwinder->BuildFrameFromPcOnly(report->allocation_trace[i]);
      frame_data.num = i;
      _LOG(log, logtype::BACKTRACE, "    %s\n", unwinder->FormatFrame(frame_data).c_str());
    }
  }

  if (report->deallocation_trace[0]) {
    _LOG(log, logtype::BACKTRACE, "\ndeallocated by thread %u:\n", report->deallocation_tid);
    unwinder->SetDisplayBuildID(true);
    for (size_t i = 0; i < 64 && report->deallocation_trace[i]; ++i) {
      unwindstack::FrameData frame_data =
          unwinder->BuildFrameFromPcOnly(report->deallocation_trace[i]);
      frame_data.num = i;
      _LOG(log, logtype::BACKTRACE, "    %s\n", unwinder->FormatFrame(frame_data).c_str());
    }
  }
}
