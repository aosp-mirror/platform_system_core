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

#include <string>
#include <vector>

#include <backtrace/BacktraceMap.h>
#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>

#include "UnwindDexFile.h"
#include "UnwindStackMap.h"

//-------------------------------------------------------------------------
UnwindStackMap::UnwindStackMap(pid_t pid) : BacktraceMap(pid) {}

UnwindStackMap::~UnwindStackMap() {
#ifndef NO_LIBDEXFILE
  for (auto& entry : dex_files_) {
    delete entry.second;
  }
#endif
}

bool UnwindStackMap::Build() {
  if (pid_ == 0) {
    pid_ = getpid();
    stack_maps_.reset(new unwindstack::LocalMaps);
  } else {
    stack_maps_.reset(new unwindstack::RemoteMaps(pid_));
  }

  // Create the process memory object.
  process_memory_ = unwindstack::Memory::CreateProcessMemory(pid_);

  // Create a JitDebug object for getting jit unwind information.
  std::vector<std::string> search_libs_{"libart.so", "libartd.so"};
  jit_debug_.reset(new unwindstack::JitDebug(process_memory_, search_libs_));

  if (!stack_maps_->Parse()) {
    return false;
  }

  // Iterate through the maps and fill in the backtrace_map_t structure.
  for (auto* map_info : *stack_maps_) {
    backtrace_map_t map;
    map.start = map_info->start;
    map.end = map_info->end;
    map.offset = map_info->offset;
    // Set to -1 so that it is demand loaded.
    map.load_bias = static_cast<uint64_t>(-1);
    map.flags = map_info->flags;
    map.name = map_info->name;

    maps_.push_back(map);
  }

  return true;
}

void UnwindStackMap::FillIn(uint64_t addr, backtrace_map_t* map) {
  BacktraceMap::FillIn(addr, map);
  if (map->load_bias != static_cast<uint64_t>(-1)) {
    return;
  }

  // Fill in the load_bias.
  unwindstack::MapInfo* map_info = stack_maps_->Find(addr);
  if (map_info == nullptr) {
    return;
  }
  map->load_bias = map_info->GetLoadBias(process_memory_);
}

uint64_t UnwindStackMap::GetLoadBias(size_t index) {
  if (index >= stack_maps_->Total()) {
    return 0;
  }

  unwindstack::MapInfo* map_info = stack_maps_->Get(index);
  if (map_info == nullptr) {
    return 0;
  }
  return map_info->GetLoadBias(process_memory_);
}

std::string UnwindStackMap::GetFunctionName(uint64_t pc, uint64_t* offset) {
  *offset = 0;
  unwindstack::Maps* maps = stack_maps();

  // Get the map for this
  unwindstack::MapInfo* map_info = maps->Find(pc);
  if (map_info == nullptr || map_info->flags & PROT_DEVICE_MAP) {
    return "";
  }

  unwindstack::Elf* elf = map_info->GetElf(process_memory(), true);

  std::string name;
  uint64_t func_offset;
  if (!elf->GetFunctionName(elf->GetRelPc(pc, map_info), &name, &func_offset)) {
    return "";
  }
  *offset = func_offset;
  return name;
}

std::shared_ptr<unwindstack::Memory> UnwindStackMap::GetProcessMemory() {
  return process_memory_;
}

#ifdef NO_LIBDEXFILE
UnwindDexFile* UnwindStackMap::GetDexFile(uint64_t, unwindstack::MapInfo*) {
  return nullptr;
}
#else
UnwindDexFile* UnwindStackMap::GetDexFile(uint64_t dex_file_offset, unwindstack::MapInfo* info) {
  // Lock while we get the data.
  std::lock_guard<std::mutex> guard(dex_lock_);
  UnwindDexFile* dex_file;
  auto entry = dex_files_.find(dex_file_offset);
  if (entry == dex_files_.end()) {
    dex_file = UnwindDexFile::Create(dex_file_offset, process_memory_.get(), info);
    dex_files_[dex_file_offset] = dex_file;
  } else {
    dex_file = entry->second;
  }
  return dex_file;
}
#endif

//-------------------------------------------------------------------------
// BacktraceMap create function.
//-------------------------------------------------------------------------
BacktraceMap* BacktraceMap::Create(pid_t pid, bool uncached) {
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
