/*
 * Copyright (C) 2017 The Android Open Source Project
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
#include <stdlib.h>
#include <sys/types.h>

#include <backtrace/BacktraceMap.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>

#include "UnwindStackMap.h"

//-------------------------------------------------------------------------
UnwindStackMap::UnwindStackMap(pid_t pid) : BacktraceMap(pid) {}

bool UnwindStackMap::Build() {
  if (pid_ == 0) {
    pid_ = getpid();
    stack_maps_.reset(new unwindstack::LocalMaps);
  } else {
    stack_maps_.reset(new unwindstack::RemoteMaps(pid_));
  }

  // Create the process memory object.
  process_memory_ = unwindstack::Memory::CreateProcessMemory(pid_);

  if (!stack_maps_->Parse()) {
    return false;
  }

  // Iterate through the maps and fill in the backtrace_map_t structure.
  for (auto& map_info : *stack_maps_) {
    backtrace_map_t map;
    map.start = map_info.start;
    map.end = map_info.end;
    map.offset = map_info.offset;
    // Set to -1 so that it is demand loaded.
    map.load_bias = static_cast<uintptr_t>(-1);
    map.flags = map_info.flags;
    map.name = map_info.name;

    maps_.push_back(map);
  }

  return true;
}

void UnwindStackMap::FillIn(uintptr_t addr, backtrace_map_t* map) {
  BacktraceMap::FillIn(addr, map);
  if (map->load_bias != static_cast<uintptr_t>(-1)) {
    return;
  }

  // Fill in the load_bias.
  unwindstack::MapInfo* map_info = stack_maps_->Find(addr);
  if (map_info == nullptr) {
    return;
  }
  unwindstack::Elf* elf = map_info->GetElf(process_memory_, true);
  map->load_bias = elf->GetLoadBias();
}

//-------------------------------------------------------------------------
// BacktraceMap create function.
//-------------------------------------------------------------------------
BacktraceMap* BacktraceMap::CreateNew(pid_t pid, bool uncached) {
  BacktraceMap* map;

  if (uncached) {
    // Force use of the base class to parse the maps when this call is made.
    map = new BacktraceMap(pid);
  } else if (pid == getpid()) {
    map = new UnwindStackMap(0);
  } else {
    map = new UnwindStackMap(pid);
  }
  if (!map->Build()) {
    delete map;
    return nullptr;
  }
  return map;
}
