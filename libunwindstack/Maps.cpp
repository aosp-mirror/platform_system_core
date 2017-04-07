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

#include <memory>
#include <string>
#include <vector>

#include "Maps.h"

MapInfo* Maps::Find(uint64_t pc) {
  if (maps_.empty()) {
    return nullptr;
  }
  size_t first = 0;
  size_t last = maps_.size();
  while (first < last) {
    size_t index = (first + last) / 2;
    MapInfo* cur = &maps_[index];
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

bool Maps::ParseLine(const char* line, MapInfo* map_info) {
  char permissions[5];
  int name_pos;
  // Linux /proc/<pid>/maps lines:
  // 6f000000-6f01e000 rwxp 00000000 00:0c 16389419   /system/lib/libcomposer.so
  if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %" SCNx64 " %*x:%*x %*d %n", &map_info->start,
             &map_info->end, permissions, &map_info->offset, &name_pos) != 4) {
    return false;
  }
  map_info->flags = PROT_NONE;
  if (permissions[0] == 'r') {
    map_info->flags |= PROT_READ;
  }
  if (permissions[1] == 'w') {
    map_info->flags |= PROT_WRITE;
  }
  if (permissions[2] == 'x') {
    map_info->flags |= PROT_EXEC;
  }

  map_info->name = &line[name_pos];
  size_t length = map_info->name.length() - 1;
  if (map_info->name[length] == '\n') {
    map_info->name.erase(length);
  }
  // Mark a device map in /dev/and not in /dev/ashmem/ specially.
  if (!map_info->name.empty() && map_info->name.substr(0, 5) == "/dev/" &&
      map_info->name.substr(5, 7) != "ashmem/") {
    map_info->flags |= MAPS_FLAGS_DEVICE_MAP;
  }

  return true;
}

bool Maps::Parse() {
  std::unique_ptr<FILE, decltype(&fclose)> fp(fopen(GetMapsFile().c_str(), "re"), fclose);
  if (!fp) {
    return false;
  }

  bool valid = true;
  char* line = nullptr;
  size_t line_len;
  while (getline(&line, &line_len, fp.get()) > 0) {
    MapInfo map_info;
    if (!ParseLine(line, &map_info)) {
      valid = false;
      break;
    }

    maps_.push_back(map_info);
  }
  free(line);

  return valid;
}

Maps::~Maps() {
  for (auto& map : maps_) {
    delete map.elf;
    map.elf = nullptr;
  }
}

bool BufferMaps::Parse() {
  const char* start_of_line = buffer_;
  do {
    std::string line;
    const char* end_of_line = strchr(start_of_line, '\n');
    if (end_of_line == nullptr) {
      line = start_of_line;
    } else {
      end_of_line++;
      line = std::string(start_of_line, end_of_line - start_of_line);
    }

    MapInfo map_info;
    if (!ParseLine(line.c_str(), &map_info)) {
      return false;
    }
    maps_.push_back(map_info);

    start_of_line = end_of_line;
  } while (start_of_line != nullptr && *start_of_line != '\0');
  return true;
}

const std::string RemoteMaps::GetMapsFile() const {
  return "/proc/" + std::to_string(pid_) + "/maps";
}

bool OfflineMaps::Parse() {
  // Format of maps information:
  //   <uint64_t> StartOffset
  //   <uint64_t> EndOffset
  //   <uint64_t> offset
  //   <uint16_t> flags
  //   <uint16_t> MapNameLength
  //   <VariableLengthValue> MapName
  android::base::unique_fd fd(TEMP_FAILURE_RETRY(open(file_.c_str(), O_RDONLY)));
  if (fd == -1) {
    return false;
  }

  std::vector<char> name;
  while (true) {
    MapInfo map_info;
    ssize_t bytes = TEMP_FAILURE_RETRY(read(fd, &map_info.start, sizeof(map_info.start)));
    if (bytes == 0) {
      break;
    }
    if (bytes == -1 || bytes != sizeof(map_info.start)) {
      return false;
    }
    bytes = TEMP_FAILURE_RETRY(read(fd, &map_info.end, sizeof(map_info.end)));
    if (bytes == -1 || bytes != sizeof(map_info.end)) {
      return false;
    }
    bytes = TEMP_FAILURE_RETRY(read(fd, &map_info.offset, sizeof(map_info.offset)));
    if (bytes == -1 || bytes != sizeof(map_info.offset)) {
      return false;
    }
    bytes = TEMP_FAILURE_RETRY(read(fd, &map_info.flags, sizeof(map_info.flags)));
    if (bytes == -1 || bytes != sizeof(map_info.flags)) {
      return false;
    }
    uint16_t len;
    bytes = TEMP_FAILURE_RETRY(read(fd, &len, sizeof(len)));
    if (bytes == -1 || bytes != sizeof(len)) {
      return false;
    }
    if (len > 0) {
      name.resize(len);
      bytes = TEMP_FAILURE_RETRY(read(fd, name.data(), len));
      if (bytes == -1 || bytes != len) {
        return false;
      }
      map_info.name = std::string(name.data(), len);
    }
    maps_.push_back(map_info);
  }
  return true;
}
