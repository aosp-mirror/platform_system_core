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

#include "android-base/macros.h"

#include "Allocator.h"

// A range [begin, end)
struct Range {
  uintptr_t begin;
  uintptr_t end;
};

// Comparator for Ranges that returns equivalence for overlapping ranges
struct compare_range {
  bool operator()(const Range& a, const Range& b) const {
    return a.end <= b.begin;
  }
};


class HeapWalker {
 public:
  HeapWalker(Allocator<HeapWalker> allocator) : allocator_(allocator),
    allocations_(allocator), allocation_bytes_(0),
	roots_(allocator), root_vals_(allocator) {
    valid_allocations_range_.end = 0;
    valid_allocations_range_.begin = ~valid_allocations_range_.end;
  }
  ~HeapWalker() {}
  bool Allocation(uintptr_t begin, uintptr_t end);
  void Root(uintptr_t begin, uintptr_t end);
  void Root(const allocator::vector<uintptr_t>& vals);

  bool DetectLeaks();

  bool Leaked(allocator::vector<Range>&, size_t limit, size_t* num_leaks,
      size_t* leak_bytes);
  size_t Allocations();
  size_t AllocationBytes();

 private:
  struct RangeInfo {
    bool referenced_from_root;
    bool referenced_from_leak;
  };
  void Walk(const Range& range, bool RangeInfo::* flag);
  DISALLOW_COPY_AND_ASSIGN(HeapWalker);
  Allocator<HeapWalker> allocator_;
  using RangeMap = allocator::map<RangeInfo, Range, compare_range>;
  RangeMap allocations_;
  size_t allocation_bytes_;
  Range valid_allocations_range_;

  allocator::vector<Range> roots_;
  allocator::vector<uintptr_t> root_vals_;
};

#endif
