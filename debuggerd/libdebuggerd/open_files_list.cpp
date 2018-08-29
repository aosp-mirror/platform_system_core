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

#define LOG_TAG "DEBUG"

#include "libdebuggerd/open_files_list.h"

#include <android/fdsan.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>
#include <utility>
#include <vector>

#include <android-base/file.h>
#include <log/log.h>
#include <unwindstack/Memory.h>

#include "libdebuggerd/utility.h"
#include "private/bionic_fdsan.h"

void populate_open_files_list(OpenFilesList* list, pid_t pid) {
  std::string fd_dir_name = "/proc/" + std::to_string(pid) + "/fd";
  std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(fd_dir_name.c_str()), closedir);
  if (dir == nullptr) {
    ALOGE("failed to open directory %s: %s", fd_dir_name.c_str(), strerror(errno));
    return;
  }

  struct dirent* de;
  while ((de = readdir(dir.get())) != nullptr) {
    if (*de->d_name == '.') {
      continue;
    }

    int fd = atoi(de->d_name);
    std::string path = fd_dir_name + "/" + std::string(de->d_name);
    std::string target;
    if (android::base::Readlink(path, &target)) {
      (*list)[fd].path = target;
    } else {
      (*list)[fd].path = "???";
      ALOGE("failed to readlink %s: %s", path.c_str(), strerror(errno));
    }
  }
}

void populate_fdsan_table(OpenFilesList* list, std::shared_ptr<unwindstack::Memory> memory,
                          uint64_t fdsan_table_address) {
  constexpr size_t inline_fds = sizeof(FdTable::entries) / sizeof(*FdTable::entries);
  static_assert(inline_fds == 128);
  size_t entry_offset = offsetof(FdTable, entries);
  for (size_t i = 0; i < inline_fds; ++i) {
    uint64_t address = fdsan_table_address + entry_offset + sizeof(FdEntry) * i;
    FdEntry entry;
    if (!memory->Read(address, &entry, sizeof(entry))) {
      ALOGE("failed to read fdsan table entry %zu: %s", i, strerror(errno));
      return;
    }
    if (entry.close_tag) {
      (*list)[i].fdsan_owner = entry.close_tag.load();
    }
  }

  size_t overflow_offset = offsetof(FdTable, overflow);
  uintptr_t overflow = 0;
  if (!memory->Read(fdsan_table_address + overflow_offset, &overflow, sizeof(overflow))) {
    ALOGE("failed to read fdsan table overflow pointer: %s", strerror(errno));
    return;
  }

  if (!overflow) {
    return;
  }

  size_t overflow_length;
  if (!memory->Read(overflow, &overflow_length, sizeof(overflow_length))) {
    ALOGE("failed to read fdsan overflow table length: %s", strerror(errno));
    return;
  }

  if (overflow_length > 131072) {
    ALOGE("unreasonable large fdsan overflow table size %zu, bailing out", overflow_length);
    return;
  }

  for (size_t i = 0; i < overflow_length; ++i) {
    int fd = i + inline_fds;
    uint64_t address = overflow + offsetof(FdTableOverflow, entries) + i * sizeof(FdEntry);
    FdEntry entry;
    if (!memory->Read(address, &entry, sizeof(entry))) {
      ALOGE("failed to read fdsan overflow entry for fd %d: %s", fd, strerror(errno));
      return;
    }
    if (entry.close_tag) {
      (*list)[fd].fdsan_owner = entry.close_tag;
    }
  }
  return;
}

void dump_open_files_list(log_t* log, const OpenFilesList& files, const char* prefix) {
  for (auto& [fd, entry] : files) {
    const std::optional<std::string>& path = entry.path;
    const std::optional<uint64_t>& fdsan_owner = entry.fdsan_owner;
    if (path && fdsan_owner) {
      const char* type = android_fdsan_get_tag_type(*fdsan_owner);
      uint64_t value = android_fdsan_get_tag_value(*fdsan_owner);
      _LOG(log, logtype::OPEN_FILES, "%sfd %i: %s (owned by %s %#" PRIx64 ")\n", prefix, fd,
           path->c_str(), type, value);
    } else if (path && !fdsan_owner) {
      _LOG(log, logtype::OPEN_FILES, "%sfd %i: %s (unowned)\n", prefix, fd, path->c_str());
    } else if (!path && fdsan_owner) {
      _LOG(log, logtype::OPEN_FILES, "%sfd %i: <MISSING> (owned by %#" PRIx64 ")\n", prefix, fd,
           *fdsan_owner);
    } else {
      ALOGE("OpenFilesList contains an entry (fd %d) with no path or owner", fd);
    }
  }
}

