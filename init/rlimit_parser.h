/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _INIT_RLIMIT_PARSER_H
#define _INIT_RLIMIT_PARSER_H

#include <sys/resource.h>

#include <string>
#include <vector>

#include "result.h"

namespace android {
namespace init {

Result<std::pair<int, rlimit>> ParseRlimit(const std::vector<std::string>& args);

}  // namespace init
}  // namespace android

#endif
