/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <errno.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <unistd.h>

#include <map>
#include <utility>

#include "Allocator.h"
#include "HeapWalker.h"
#include "LeakFolding.h"
#include "ScopedSignalHandler.h"
#include "log.h"

namespace android {

bool HeapWalker::Allocation(uintptr_t begin, uintptr_t end) {
  if (end == begin) {
    end = begin + 1;
  }
  Range range{begin, end};
  if (valid_mappings_range_.end != 0 &&
      (begin < valid_mappings_range_.begin || end > valid_mappings_range_.end)) {
    MEM_LOG_ALWAYS_FATAL("allocation %p-%p is outside mapping range %p-%p",
                         reinterpret_cast<void*>(begin), reinterpret_cast<void*>(end),
                         reinterpret_cast<void*>(valid_mappings_range_.begin),
                         reinterpret_cast<void*>(valid_mappings_range_.end));
  }
  auto inserted = allocations_.insert(std::pair<Range, AllocationInfo>(range, AllocationInfo{}));
  if (inserted.second) {
    valid_allocations_range_.begin = std::min(valid_allocations_range_.begin, begin);
    valid_allocations_range_.end = std::max(valid_allocations_range_.end, end);
    allocation_bytes_ += range.size();
    return true;
  } else {
    Range overlap = inserted.first->first;
    if (overlap != range) {
      MEM_ALOGE("range %p-%p overlaps with existing range %p-%p", reinterpret_cast<void*>(begin),
                reinterpret_cast<void*>(end), reinterpret_cast<void*>(overlap.begin),
                reinterpret_cast<void*>(overlap.end));
    }
    return false;
  }
}

// Sanitizers may consider certain memory inaccessible through certain pointers.
// With MTE this will need to use unchecked instructions or disable tag checking globally.
static uintptr_t ReadWordAtAddressUnsafe(uintptr_t word_ptr)
    __attribute__((no_sanitize("address", "hwaddress"))) {
  return *reinterpret_cast<uintptr_t*>(word_ptr);
}

bool HeapWalker::WordContainsAllocationPtr(uintptr_t word_ptr, Range* range, AllocationInfo** info) {
  walking_ptr_ = word_ptr;
  // This access may segfault if the process under test has done something strange,
  // for example mprotect(PROT_NONE) on a native heap page.  If so, it will be
  // caught and handled by mmaping a zero page over the faulting page.
  uintptr_t value = ReadWordAtAddressUnsafe(word_ptr);
  walking_ptr_ = 0;
  if (value >= valid_allocations_range_.begin && value < valid_allocations_range_.end) {
    AllocationMap::iterator it = allocations_.find(Range{value, value + 1});
    if (it != allocations_.end()) {
      *range = it->first;
      *info = &it->second;
      return true;
    }
  }
  return false;
}

void HeapWalker::RecurseRoot(const Range& root) {
  allocator::vector<Range> to_do(1, root, allocator_);
  while (!to_do.empty()) {
    Range range = to_do.back();
    to_do.pop_back();

    walking_range_ = range;
    ForEachPtrInRange(range, [&](Range& ref_range, AllocationInfo* ref_info) {
      if (!ref_info->referenced_from_root) {
        ref_info->referenced_from_root = true;
        to_do.push_back(ref_range);
      }
    });
    walking_range_ = Range{0, 0};
  }
}

void HeapWalker::Mapping(uintptr_t begin, uintptr_t end) {
  valid_mappings_range_.begin = std::min(valid_mappings_range_.begin, begin);
  valid_mappings_range_.end = std::max(valid_mappings_range_.end, end);
}

void HeapWalker::Root(uintptr_t begin, uintptr_t end) {
  roots_.push_back(Range{begin, end});
}

void HeapWalker::Root(const allocator::vector<uintptr_t>& vals) {
  root_vals_.insert(root_vals_.end(), vals.begin(), vals.end());
}

size_t HeapWalker::Allocations() {
  return allocations_.size();
}

size_t HeapWalker::AllocationBytes() {
  return allocation_bytes_;
}

bool HeapWalker::DetectLeaks() {
  // Recursively walk pointers from roots to mark referenced allocations
  for (auto it = roots_.begin(); it != roots_.end(); it++) {
    RecurseRoot(*it);
  }

  Range vals;
  vals.begin = reinterpret_cast<uintptr_t>(root_vals_.data());
  vals.end = vals.begin + root_vals_.size() * sizeof(uintptr_t);

  RecurseRoot(vals);

  if (segv_page_count_ > 0) {
    MEM_ALOGE("%zu pages skipped due to segfaults", segv_page_count_);
  }

  return true;
}

bool HeapWalker::Leaked(allocator::vector<Range>& leaked, size_t limit, size_t* num_leaks_out,
                        size_t* leak_bytes_out) {
  leaked.clear();

  size_t num_leaks = 0;
  size_t leak_bytes = 0;
  for (auto it = allocations_.begin(); it != allocations_.end(); it++) {
    if (!it->second.referenced_from_root) {
      num_leaks++;
      leak_bytes += it->first.end - it->first.begin;
    }
  }

  size_t n = 0;
  for (auto it = allocations_.begin(); it != allocations_.end(); it++) {
    if (!it->second.referenced_from_root) {
      if (n++ < limit) {
        leaked.push_back(it->first);
      }
    }
  }

  if (num_leaks_out) {
    *num_leaks_out = num_leaks;
  }
  if (leak_bytes_out) {
    *leak_bytes_out = leak_bytes;
  }

  return true;
}

static bool MapOverPage(void* addr) {
  const size_t page_size = sysconf(_SC_PAGE_SIZE);
  void* page = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(addr) & ~(page_size - 1));

  void* ret = mmap(page, page_size, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0);
  if (ret == MAP_FAILED) {
    MEM_ALOGE("failed to map page at %p: %s", page, strerror(errno));
    return false;
  }

  return true;
}

void HeapWalker::HandleSegFault(ScopedSignalHandler& handler, int signal, siginfo_t* si,
                                void* /*uctx*/) {
  uintptr_t addr = reinterpret_cast<uintptr_t>(si->si_addr);
  if (addr != walking_ptr_) {
    handler.reset();
    return;
  }
  if (!segv_logged_) {
    MEM_ALOGW("failed to read page at %p, signal %d", si->si_addr, signal);
    if (walking_range_.begin != 0U) {
      MEM_ALOGW("while walking range %p-%p", reinterpret_cast<void*>(walking_range_.begin),
                reinterpret_cast<void*>(walking_range_.end));
    }
    segv_logged_ = true;
  }
  segv_page_count_++;
  if (!MapOverPage(si->si_addr)) {
    handler.reset();
  }
}

Allocator<ScopedSignalHandler::SignalFnMap>::unique_ptr ScopedSignalHandler::handler_map_;

}  // namespace android
