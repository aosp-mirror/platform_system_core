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

#include <fcntl.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>

#include <android-base/unique_fd.h>

#include "LineBuffer.h"
#include "ProcessMappings.h"
#include "log.h"

namespace android {

// This function is not re-entrant since it uses a static buffer for
// the line data.
bool ProcessMappings(pid_t pid, allocator::vector<Mapping>& mappings) {
  char map_buffer[1024];
  snprintf(map_buffer, sizeof(map_buffer), "/proc/%d/maps", pid);
  android::base::unique_fd fd(open(map_buffer, O_RDONLY));
  if (fd == -1) {
    return false;
  }

  LineBuffer line_buf(fd, map_buffer, sizeof(map_buffer));
  char* line;
  size_t line_len;
  while (line_buf.GetLine(&line, &line_len)) {
    int name_pos;
    char perms[5];
    Mapping mapping{};
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s %*x %*x:%*x %*d %n", &mapping.begin,
               &mapping.end, perms, &name_pos) == 3) {
      if (perms[0] == 'r') {
        mapping.read = true;
      }
      if (perms[1] == 'w') {
        mapping.write = true;
      }
      if (perms[2] == 'x') {
        mapping.execute = true;
      }
      if (perms[3] == 'p') {
        mapping.priv = true;
      }
      if ((size_t)name_pos < line_len) {
        strlcpy(mapping.name, line + name_pos, sizeof(mapping.name));
      }
      mappings.emplace_back(mapping);
    }
  }
  return true;
}

}  // namespace android
