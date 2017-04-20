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

#include <sys/types.h>
#include <unistd.h>

#include <memory>
#include <string>

#include "Elf.h"
#include "MapInfo.h"
#include "Maps.h"
#include "Memory.h"

Memory* MapInfo::CreateMemory(pid_t pid) {
  if (end <= start) {
    return nullptr;
  }

  elf_offset = 0;

  // First try and use the file associated with the info.
  if (!name.empty()) {
    // Fail on device maps.
    if (flags & MAPS_FLAGS_DEVICE_MAP) {
      return nullptr;
    }

    std::unique_ptr<MemoryFileAtOffset> file_memory(new MemoryFileAtOffset);
    uint64_t map_size;
    if (offset != 0) {
      // Only map in a piece of the file.
      map_size = end - start;
    } else {
      map_size = UINT64_MAX;
    }
    if (file_memory->Init(name, offset, map_size)) {
      // It's possible that a non-zero offset might not be pointing to
      // valid elf data. Check if this is a valid elf, and if not assume
      // that this was meant to incorporate the entire file.
      if (offset != 0 && !Elf::IsValidElf(file_memory.get())) {
        // Don't bother checking the validity that will happen on the elf init.
        if (file_memory->Init(name, 0)) {
          elf_offset = offset;
          return file_memory.release();
        }
        // Fall through if the init fails.
      } else {
        return file_memory.release();
      }
    }
  }

  Memory* memory = nullptr;
  if (pid == getpid()) {
    memory = new MemoryLocal();
  } else {
    memory = new MemoryRemote(pid);
  }
  return new MemoryRange(memory, start, end);
}

Elf* MapInfo::GetElf(pid_t pid, bool) {
  if (elf) {
    return elf;
  }

  elf = new Elf(CreateMemory(pid));
  elf->Init();
  // If the init fails, keep the elf around as an invalid object so we
  // don't try to reinit the object.
  return elf;
}
