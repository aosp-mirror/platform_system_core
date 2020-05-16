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

#include "adb_unique_fd.h"

#include <optional>
#include <string>

#include "sysdeps.h"

namespace incremental {

using Files = std::vector<std::string>;
using Args = std::vector<std::string_view>;

bool can_install(const Files& files);
std::optional<Process> install(const Files& files, const Args& passthrough_args, bool silent);

enum class Result { Success, Failure, None };
Result wait_for_installation(int read_fd);

}  // namespace incremental
