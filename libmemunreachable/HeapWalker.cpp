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

#include <inttypes.h>

#include <map>
#include <utility>

#include "Allocator.h"
#include "HeapWalker.h"
#include "log.h"

bool HeapWalker::Allocation(uintptr_t begin, uintptr_t end) {
  if (end == begin) {
    end = begin + 1;
  }
  auto inserted = allocations_.insert(std::pair<Range, RangeInfo>(Range{begin, end}, RangeInfo{false, false}));
  if (inserted.second) {
    valid_allocations_range_.begin = std::min(valid_allocations_range_.begin, begin);
    valid_allocations_range_.end = std::max(valid_allocations_range_.end, end);
    allocation_bytes_ += end - begin;
    return true;
  } else {
    Range overlap = inserted.first->first;
    ALOGE("range %p-%p overlaps with existing range %p-%p",
        reinterpret_cast<void*>(begin),
        reinterpret_cast<void*>(end),
        reinterpret_cast<void*>(overlap.begin),
        reinterpret_cast<void*>(overlap.end));
    return false;
  }
}

void HeapWalker::Walk(const Range& range, bool RangeInfo::*flag) {
  allocator::vector<Range> to_do(1, range, allocator_);
  while (!to_do.empty()) {
    Range range = to_do.back();
    to_do.pop_back();
    uintptr_t begin = (range.begin + (sizeof(uintptr_t) - 1)) & ~(sizeof(uintptr_t) - 1);
    // TODO(ccross): we might need to consider a pointer to the end of a buffer
    // to be inside the buffer, which means the common case of a pointer to the
    // beginning of a buffer may keep two ranges live.
    for (uintptr_t i = begin; i < range.end; i += sizeof(uintptr_t)) {
      uintptr_t val = *reinterpret_cast<uintptr_t*>(i);
      if (val >= valid_allocations_range_.begin && val < valid_allocations_range_.end) {
        RangeMap::iterator it = allocations_.find(Range{val, val + 1});
        if (it != allocations_.end()) {
          if (!(it->second.*flag)) {
            to_do.push_back(it->first);
            it->second.*flag = true;
          }
        }
      }
    }
  }
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
  for (auto it = roots_.begin(); it != roots_.end(); it++) {
    Walk(*it, &RangeInfo::referenced_from_root);
  }

  Range vals;
  vals.begin = reinterpret_cast<uintptr_t>(root_vals_.data());
  vals.end = vals.begin + root_vals_.size() * sizeof(uintptr_t);
  Walk(vals, &RangeInfo::referenced_from_root);

  for (auto it = allocations_.begin(); it != allocations_.end(); it++) {
    if (!it->second.referenced_from_root) {
      Walk(it->first, &RangeInfo::referenced_from_leak);
    }
  }

  return true;
}

bool HeapWalker::Leaked(allocator::vector<Range>& leaked, size_t limit,
    size_t* num_leaks_out, size_t* leak_bytes_out) {
  DetectLeaks();
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
      if (n++ <= limit) {
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
