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

#include "Allocator.h"
#include "HeapWalker.h"
#include "LeakFolding.h"
#include "Tarjan.h"
#include "log.h"

namespace android {

// Converts possibly cyclic graph of leaks to a DAG by combining
// strongly-connected components into a object, stored in the scc pointer
// of each node in the component.
void LeakFolding::ComputeDAG() {
  SCCList<LeakInfo> scc_list{allocator_};
  Tarjan(leak_graph_, scc_list);

  Allocator<SCCInfo> scc_allocator = allocator_;

  for (auto& scc_nodes : scc_list) {
    Allocator<SCCInfo>::unique_ptr leak_scc;
    leak_scc = scc_allocator.make_unique(scc_allocator);

    for (auto& node : scc_nodes) {
      node->ptr->scc = leak_scc.get();
      leak_scc->count++;
      leak_scc->size += node->ptr->range.size();
    }

    leak_scc_.emplace_back(std::move(leak_scc));
  }

  for (auto& it : leak_map_) {
    LeakInfo& leak = it.second;
    for (auto& ref : leak.node.references_out) {
      if (leak.scc != ref->ptr->scc) {
        leak.scc->node.Edge(&ref->ptr->scc->node);
      }
    }
  }
}

void LeakFolding::AccumulateLeaks(SCCInfo* dominator) {
  std::function<void(SCCInfo*)> walk([&](SCCInfo* scc) {
    if (scc->accumulator != dominator) {
      scc->accumulator = dominator;
      dominator->cuumulative_size += scc->size;
      dominator->cuumulative_count += scc->count;
      scc->node.Foreach([&](SCCInfo* ref) { walk(ref); });
    }
  });
  walk(dominator);
}

bool LeakFolding::FoldLeaks() {
  Allocator<LeakInfo> leak_allocator = allocator_;

  // Find all leaked allocations insert them into leak_map_ and leak_graph_
  heap_walker_.ForEachAllocation([&](const Range& range, HeapWalker::AllocationInfo& allocation) {
    if (!allocation.referenced_from_root) {
      auto it = leak_map_.emplace(std::piecewise_construct, std::forward_as_tuple(range),
                                  std::forward_as_tuple(range, allocator_));
      LeakInfo& leak = it.first->second;
      leak_graph_.push_back(&leak.node);
    }
  });

  // Find references between leaked allocations and connect them in leak_graph_
  for (auto& it : leak_map_) {
    LeakInfo& leak = it.second;
    heap_walker_.ForEachPtrInRange(leak.range,
                                   [&](Range& ptr_range, HeapWalker::AllocationInfo* ptr_info) {
                                     if (!ptr_info->referenced_from_root) {
                                       LeakInfo* ptr_leak = &leak_map_.at(ptr_range);
                                       leak.node.Edge(&ptr_leak->node);
                                     }
                                   });
  }

  // Convert the cyclic graph to a DAG by grouping strongly connected components
  ComputeDAG();

  // Compute dominators and cuumulative sizes
  for (auto& scc : leak_scc_) {
    if (scc->node.references_in.size() == 0) {
      scc->dominator = true;
      AccumulateLeaks(scc.get());
    }
  }

  return true;
}

bool LeakFolding::Leaked(allocator::vector<LeakFolding::Leak>& leaked, size_t* num_leaks_out,
                         size_t* leak_bytes_out) {
  size_t num_leaks = 0;
  size_t leak_bytes = 0;
  for (auto& it : leak_map_) {
    const LeakInfo& leak = it.second;
    num_leaks++;
    leak_bytes += leak.range.size();
  }

  for (auto& it : leak_map_) {
    const LeakInfo& leak = it.second;
    if (leak.scc->dominator) {
      leaked.emplace_back(Leak{leak.range, leak.scc->cuumulative_count - 1,
                               leak.scc->cuumulative_size - leak.range.size()});
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

}  // namespace android
