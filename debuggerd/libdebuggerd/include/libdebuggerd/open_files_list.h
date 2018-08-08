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

#pragma once

#include <stdint.h>
#include <sys/types.h>

#include <map>
#include <optional>
#include <string>
#include <utility>

#include "utility.h"

struct FDInfo {
  std::optional<std::string> path;
  std::optional<uint64_t> fdsan_owner;
};

using OpenFilesList = std::map<int, FDInfo>;

// Populates the given list with open files for the given process.
void populate_open_files_list(OpenFilesList* list, pid_t pid);

// Populates the given list with the target process's fdsan table.
void populate_fdsan_table(OpenFilesList* list, std::shared_ptr<unwindstack::Memory> memory,
                          uint64_t fdsan_table_address);

// Dumps the open files list to the log.
void dump_open_files_list(log_t* log, const OpenFilesList& files, const char* prefix);
