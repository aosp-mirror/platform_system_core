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
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <procinfo/process_map.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <string>
#include <vector>

#include <unwindstack/Elf.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>

namespace unwindstack {

MapInfo* Maps::Find(uint64_t pc) {
  if (maps_.empty()) {
    return nullptr;
  }
  size_t first = 0;
  size_t last = maps_.size();
  while (first < last) {
    size_t index = (first + last) / 2;
    MapInfo* cur = maps_[index];
    if (pc >= cur->start && pc < cur->end) {
      return cur;
    } else if (pc < cur->start) {
      last = index;
    } else {
      first = index + 1;
    }
  }
  return nullptr;
}

bool Maps::Parse() {
  return android::procinfo::ReadMapFile(
      GetMapsFile(),
      [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, const char* name) {
        // Mark a device map in /dev/ and not in /dev/ashmem/ specially.
        if (strncmp(name, "/dev/", 5) == 0 && strncmp(name + 5, "ashmem/", 7) != 0) {
          flags |= unwindstack::MAPS_FLAGS_DEVICE_MAP;
        }
        maps_.push_back(new MapInfo(start, end, pgoff, flags, name));
      });
}

void Maps::Add(uint64_t start, uint64_t end, uint64_t offset, uint64_t flags,
               const std::string& name, uint64_t load_bias) {
  MapInfo* map_info = new MapInfo(start, end, offset, flags, name);
  map_info->load_bias = load_bias;
  maps_.push_back(map_info);
}

void Maps::Sort() {
  std::sort(maps_.begin(), maps_.end(),
            [](const MapInfo* a, const MapInfo* b) { return a->start < b->start; });
}

Maps::~Maps() {
  for (auto& map : maps_) {
    delete map;
  }
}

bool BufferMaps::Parse() {
  std::string content(buffer_);
  return android::procinfo::ReadMapFileContent(
      &content[0],
      [&](uint64_t start, uint64_t end, uint16_t flags, uint64_t pgoff, const char* name) {
        // Mark a device map in /dev/ and not in /dev/ashmem/ specially.
        if (strncmp(name, "/dev/", 5) == 0 && strncmp(name + 5, "ashmem/", 7) != 0) {
          flags |= unwindstack::MAPS_FLAGS_DEVICE_MAP;
        }
        maps_.push_back(new MapInfo(start, end, pgoff, flags, name));
      });
}

const std::string RemoteMaps::GetMapsFile() const {
  return "/proc/" + std::to_string(pid_) + "/maps";
}

}  // namespace unwindstack
