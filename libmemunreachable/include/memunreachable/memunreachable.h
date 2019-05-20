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

#ifndef LIBMEMUNREACHABLE_MEMUNREACHABLE_H_
#define LIBMEMUNREACHABLE_MEMUNREACHABLE_H_

#include <string.h>
#include <sys/cdefs.h>

#ifdef __cplusplus

#include <string>
#include <vector>

namespace android {

struct Leak {
  uintptr_t begin = 0;
  size_t size = 0;

  size_t referenced_count = 0;
  size_t referenced_size = 0;

  size_t similar_count = 0;
  size_t similar_size = 0;
  size_t similar_referenced_count = 0;
  size_t similar_referenced_size = 0;

  size_t total_size = 0;

  static const size_t contents_length = 32;
  char contents[contents_length] = {};

  struct Backtrace {
    size_t num_frames = 0;

    static const size_t max_frames = 16;
    uintptr_t frames[max_frames] = {};

    size_t reserved[8] = {};
  } backtrace;

  size_t reserved[8] = {};

  std::string ToString(bool log_contents) const;
};

struct UnreachableMemoryInfo {
  std::vector<Leak> leaks;
  size_t num_leaks = 0;
  size_t leak_bytes = 0;
  size_t num_allocations = 0;
  size_t allocation_bytes = 0;

  size_t version = 0;  // Must be 0
  size_t reserved[8] = {};

  UnreachableMemoryInfo() {}
  ~UnreachableMemoryInfo();

  std::string ToString(bool log_contents) const;
};

bool GetUnreachableMemory(UnreachableMemoryInfo& info, size_t limit = 100);

std::string GetUnreachableMemoryString(bool log_contents = false, size_t limit = 100);

}  // namespace android

#endif

__BEGIN_DECLS

bool LogUnreachableMemory(bool log_contents, size_t limit);

bool NoLeaks();

__END_DECLS

#endif  // LIBMEMUNREACHABLE_MEMUNREACHABLE_H_
