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

#ifndef LIBMEMUNREACHABLE_HEAP_WALKER_H_
#define LIBMEMUNREACHABLE_HEAP_WALKER_H_

#include <signal.h>

#include "android-base/macros.h"

#include "Allocator.h"
#include "ScopedSignalHandler.h"
#include "Tarjan.h"

namespace android {

// A range [begin, end)
struct Range {
  uintptr_t begin;
  uintptr_t end;

  size_t size() const { return end - begin; };
  bool operator==(const Range& other) const {
    return this->begin == other.begin && this->end == other.end;
  }
  bool operator!=(const Range& other) const { return !(*this == other); }
};

// Comparator for Ranges that returns equivalence for overlapping ranges
struct compare_range {
  bool operator()(const Range& a, const Range& b) const { return a.end <= b.begin; }
};

class HeapWalker {
 public:
  explicit HeapWalker(Allocator<HeapWalker> allocator)
      : allocator_(allocator),
        allocations_(allocator),
        allocation_bytes_(0),
        roots_(allocator),
        root_vals_(allocator),
        segv_handler_(allocator),
        walking_ptr_(0) {
    valid_allocations_range_.end = 0;
    valid_allocations_range_.begin = ~valid_allocations_range_.end;

    segv_handler_.install(
        SIGSEGV, [=](ScopedSignalHandler& handler, int signal, siginfo_t* siginfo, void* uctx) {
          this->HandleSegFault(handler, signal, siginfo, uctx);
        });
  }

  ~HeapWalker() {}
  bool Allocation(uintptr_t begin, uintptr_t end);
  void Root(uintptr_t begin, uintptr_t end);
  void Root(const allocator::vector<uintptr_t>& vals);

  bool DetectLeaks();

  bool Leaked(allocator::vector<Range>&, size_t limit, size_t* num_leaks, size_t* leak_bytes);
  size_t Allocations();
  size_t AllocationBytes();

  template <class F>
  void ForEachPtrInRange(const Range& range, F&& f);

  template <class F>
  void ForEachAllocation(F&& f);

  struct AllocationInfo {
    bool referenced_from_root;
  };

 private:
  void RecurseRoot(const Range& root);
  bool WordContainsAllocationPtr(uintptr_t ptr, Range* range, AllocationInfo** info);
  void HandleSegFault(ScopedSignalHandler&, int, siginfo_t*, void*);

  DISALLOW_COPY_AND_ASSIGN(HeapWalker);
  Allocator<HeapWalker> allocator_;
  using AllocationMap = allocator::map<Range, AllocationInfo, compare_range>;
  AllocationMap allocations_;
  size_t allocation_bytes_;
  Range valid_allocations_range_;

  allocator::vector<Range> roots_;
  allocator::vector<uintptr_t> root_vals_;

  ScopedSignalHandler segv_handler_;
  uintptr_t walking_ptr_;
};

template <class F>
inline void HeapWalker::ForEachPtrInRange(const Range& range, F&& f) {
  uintptr_t begin = (range.begin + (sizeof(uintptr_t) - 1)) & ~(sizeof(uintptr_t) - 1);
  // TODO(ccross): we might need to consider a pointer to the end of a buffer
  // to be inside the buffer, which means the common case of a pointer to the
  // beginning of a buffer may keep two ranges live.
  for (uintptr_t i = begin; i < range.end; i += sizeof(uintptr_t)) {
    Range ref_range;
    AllocationInfo* ref_info;
    if (WordContainsAllocationPtr(i, &ref_range, &ref_info)) {
      f(ref_range, ref_info);
    }
  }
}

template <class F>
inline void HeapWalker::ForEachAllocation(F&& f) {
  for (auto& it : allocations_) {
    const Range& range = it.first;
    HeapWalker::AllocationInfo& allocation = it.second;
    f(range, allocation);
  }
}

}  // namespace android

#endif
