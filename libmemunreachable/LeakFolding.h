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

#ifndef LIBMEMUNREACHABLE_LEAK_FOLDING_H_
#define LIBMEMUNREACHABLE_LEAK_FOLDING_H_

#include "HeapWalker.h"

namespace android {

class LeakFolding {
 public:
  LeakFolding(Allocator<void> allocator, HeapWalker& heap_walker)
      : allocator_(allocator),
        heap_walker_(heap_walker),
        leak_map_(allocator),
        leak_graph_(allocator),
        leak_scc_(allocator) {}

  bool FoldLeaks();

  struct Leak {
    const Range range;
    size_t referenced_count;
    size_t referenced_size;
  };

  bool Leaked(allocator::vector<Leak>& leaked, size_t* num_leaks_out, size_t* leak_bytes_out);

 private:
  DISALLOW_COPY_AND_ASSIGN(LeakFolding);
  Allocator<void> allocator_;
  HeapWalker& heap_walker_;

  struct SCCInfo {
   public:
    Node<SCCInfo> node;

    size_t count;
    size_t size;

    size_t cuumulative_count;
    size_t cuumulative_size;

    bool dominator;
    SCCInfo* accumulator;

    explicit SCCInfo(Allocator<SCCInfo> allocator)
        : node(this, allocator),
          count(0),
          size(0),
          cuumulative_count(0),
          cuumulative_size(0),
          dominator(false),
          accumulator(nullptr) {}

   private:
    SCCInfo(SCCInfo&&) = delete;
    DISALLOW_COPY_AND_ASSIGN(SCCInfo);
  };

  struct LeakInfo {
   public:
    Node<LeakInfo> node;

    const Range range;

    SCCInfo* scc;

    LeakInfo(const Range& range, Allocator<LeakInfo> allocator)
        : node(this, allocator), range(range), scc(nullptr) {}

   private:
    DISALLOW_COPY_AND_ASSIGN(LeakInfo);
  };

  void ComputeDAG();
  void AccumulateLeaks(SCCInfo* dominator);

  allocator::map<Range, LeakInfo, compare_range> leak_map_;
  Graph<LeakInfo> leak_graph_;
  allocator::vector<Allocator<SCCInfo>::unique_ptr> leak_scc_;
};

}  // namespace android

#endif  // LIBMEMUNREACHABLE_LEAK_FOLDING_H_
