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

#ifndef LIBMEMUNREACHABLE_PROCESS_MAPPING_H_
#define LIBMEMUNREACHABLE_PROCESS_MAPPING_H_

#include <string.h>

#include "Allocator.h"

namespace android {

struct Mapping {
  uintptr_t begin;
  uintptr_t end;
  bool read;
  bool write;
  bool execute;
  char name[96];

  Mapping() {}
  Mapping(uintptr_t begin, uintptr_t end, bool read, bool write, bool execute, const char* name)
      : begin(begin), end(end), read(read), write(write), execute(execute) {
    strlcpy(this->name, name, sizeof(this->name));
  }
};

// This function is not re-entrant since it uses a static buffer for
// the line data.
bool ProcessMappings(pid_t pid, allocator::vector<Mapping>& mappings);

}  // namespace android

#endif  // LIBMEMUNREACHABLE_PROCESS_MAPPING_H_
