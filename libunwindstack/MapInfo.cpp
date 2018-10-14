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

#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <mutex>
#include <string>

#include <unwindstack/Elf.h>
#include <unwindstack/MapInfo.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

Memory* MapInfo::GetFileMemory() {
  std::unique_ptr<MemoryFileAtOffset> memory(new MemoryFileAtOffset);
  if (offset == 0) {
    if (memory->Init(name, 0)) {
      return memory.release();
    }
    return nullptr;
  }

  // There are two possibilities when the offset is non-zero.
  // - There is an elf file embedded in a file.
  // - The whole file is an elf file, and the offset needs to be saved.
  //
  // Map in just the part of the file for the map. If this is not
  // a valid elf, then reinit as if the whole file is an elf file.
  // If the offset is a valid elf, then determine the size of the map
  // and reinit to that size. This is needed because the dynamic linker
  // only maps in a portion of the original elf, and never the symbol
  // file data.
  uint64_t map_size = end - start;
  if (!memory->Init(name, offset, map_size)) {
    return nullptr;
  }

  uint64_t max_size;
  if (!Elf::GetInfo(memory.get(), &max_size)) {
    // Init as if the whole file is an elf.
    if (memory->Init(name, 0)) {
      elf_offset = offset;
      return memory.release();
    }
    return nullptr;
  }

  if (max_size > map_size) {
    if (memory->Init(name, offset, max_size)) {
      return memory.release();
    }
    // Try to reinit using the default map_size.
    if (memory->Init(name, offset, map_size)) {
      return memory.release();
    }
    return nullptr;
  }
  return memory.release();
}

Memory* MapInfo::CreateMemory(const std::shared_ptr<Memory>& process_memory) {
  if (end <= start) {
    return nullptr;
  }

  elf_offset = 0;

  // Fail on device maps.
  if (flags & MAPS_FLAGS_DEVICE_MAP) {
    return nullptr;
  }

  // First try and use the file associated with the info.
  if (!name.empty()) {
    Memory* memory = GetFileMemory();
    if (memory != nullptr) {
      return memory;
    }
  }

  // If the map isn't readable, don't bother trying to read from process memory.
  if (!(flags & PROT_READ)) {
    return nullptr;
  }

  // Need to verify that this elf is valid. It's possible that
  // only part of the elf file to be mapped into memory is in the executable
  // map. In this case, there will be another read-only map that includes the
  // first part of the elf file. This is done if the linker rosegment
  // option is used.
  std::unique_ptr<MemoryRange> memory(new MemoryRange(process_memory, start, end - start, 0));
  if (Elf::IsValidElf(memory.get())) {
    return memory.release();
  }

  if (name.empty() || maps_ == nullptr) {
    return nullptr;
  }

  // Find the read-only map that has the same name and has an offset closest
  // to the current offset but less than the offset of the current map.
  // For shared libraries, there should be a r-x map that has a non-zero
  // offset and then a r-- map that has a zero offset.
  // For shared libraries loaded from an apk, there should be a r-x map that
  // has a non-zero offset and then a r-- map that has a non-zero offset less
  // than the offset from the r-x map.
  uint64_t closest_offset = 0;
  MapInfo* ro_map_info = nullptr;
  for (auto map_info : *maps_) {
    if (map_info->flags == PROT_READ && map_info->name == name && map_info->offset < offset &&
        map_info->offset >= closest_offset) {
      ro_map_info = map_info;
      closest_offset = ro_map_info->offset;
    }
  }

  if (ro_map_info != nullptr) {
    // Make sure that relative pc values are corrected properly.
    elf_offset = offset - closest_offset;

    MemoryRanges* ranges = new MemoryRanges;
    ranges->Insert(new MemoryRange(process_memory, ro_map_info->start,
                                   ro_map_info->end - ro_map_info->start, 0));
    ranges->Insert(new MemoryRange(process_memory, start, end - start, elf_offset));

    return ranges;
  }
  return nullptr;
}

Elf* MapInfo::GetElf(const std::shared_ptr<Memory>& process_memory, bool init_gnu_debugdata) {
  // Make sure no other thread is trying to add the elf to this map.
  std::lock_guard<std::mutex> guard(mutex_);

  if (elf.get() != nullptr) {
    return elf.get();
  }

  bool locked = false;
  if (Elf::CachingEnabled() && !name.empty()) {
    Elf::CacheLock();
    locked = true;
    if (Elf::CacheGet(this)) {
      Elf::CacheUnlock();
      return elf.get();
    }
  }

  Memory* memory = CreateMemory(process_memory);
  if (locked) {
    if (Elf::CacheAfterCreateMemory(this)) {
      delete memory;
      Elf::CacheUnlock();
      return elf.get();
    }
  }
  elf.reset(new Elf(memory));
  // If the init fails, keep the elf around as an invalid object so we
  // don't try to reinit the object.
  elf->Init(init_gnu_debugdata);

  if (locked) {
    Elf::CacheAdd(this);
    Elf::CacheUnlock();
  }
  return elf.get();
}

uint64_t MapInfo::GetLoadBias(const std::shared_ptr<Memory>& process_memory) {
  uint64_t cur_load_bias = load_bias.load();
  if (cur_load_bias != static_cast<uint64_t>(-1)) {
    return cur_load_bias;
  }

  {
    // Make sure no other thread is trying to add the elf to this map.
    std::lock_guard<std::mutex> guard(mutex_);
    if (elf != nullptr) {
      if (elf->valid()) {
        cur_load_bias = elf->GetLoadBias();
        load_bias = cur_load_bias;
        return cur_load_bias;
      } else {
        load_bias = 0;
        return 0;
      }
    }
  }

  // Call lightweight static function that will only read enough of the
  // elf data to get the load bias.
  std::unique_ptr<Memory> memory(CreateMemory(process_memory));
  cur_load_bias = Elf::GetLoadBias(memory.get());
  load_bias = cur_load_bias;
  return cur_load_bias;
}

}  // namespace unwindstack
