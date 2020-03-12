/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <string.h>
#include <string>

struct ProcessInfo {
  const static size_t kMaxArchNameLength = 16;

  uint64_t pid;
  bool debuggable;
  bool profileable;
  int32_t arch_name_length;            // length of architecture name in bytes
  char arch_name[kMaxArchNameLength];  // ISA name, e.g., "arm64"

  ProcessInfo() : pid(0), debuggable(false), profileable(false), arch_name_length(0) {}

  ProcessInfo(uint64_t pid, bool dbg, bool prof, const std::string& arch)
      : pid(pid), debuggable(dbg), profileable(prof) {
    arch_name_length = std::min(arch.size(), kMaxArchNameLength);
    memcpy(arch_name, arch.data(), arch_name_length);
  }
};
