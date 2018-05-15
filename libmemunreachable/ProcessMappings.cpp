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
#include <string.h>
#include <unistd.h>

#include <android-base/unique_fd.h>
#include <procinfo/process_map.h>

#include "ProcessMappings.h"

namespace android {

struct ReadMapCallback {
  ReadMapCallback(allocator::vector<Mapping>& mappings) : mappings_(mappings) {}

  void operator()(uint64_t start, uint64_t end, uint16_t flags, uint64_t, const char* name) const {
    mappings_.emplace_back(start, end, flags & PROT_READ, flags & PROT_WRITE, flags & PROT_EXEC,
                           name);
  }

  allocator::vector<Mapping>& mappings_;
};

bool ProcessMappings(pid_t pid, allocator::vector<Mapping>& mappings) {
  char map_buffer[1024];
  snprintf(map_buffer, sizeof(map_buffer), "/proc/%d/maps", pid);
  android::base::unique_fd fd(open(map_buffer, O_RDONLY));
  if (fd == -1) {
    return false;
  }
  allocator::string content(mappings.get_allocator());
  ssize_t n;
  while ((n = TEMP_FAILURE_RETRY(read(fd, map_buffer, sizeof(map_buffer)))) > 0) {
    content.append(map_buffer, n);
  }
  ReadMapCallback callback(mappings);
  return android::procinfo::ReadMapFileContent(&content[0], callback);
}

}  // namespace android
