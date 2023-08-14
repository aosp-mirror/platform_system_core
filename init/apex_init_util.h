/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <set>
#include <string>
#include <vector>

#include "result.h"

namespace android {
namespace init {

// Scans apex_dir (/apex) to get the list of active APEXes.
std::set<std::string> GetApexListFrom(const std::string& apex_dir);

// Parse all RC scripts for a given apex.
Result<void> ParseRcScriptsFromApex(const std::string& apex_name);

// Parse all RC scripts for all apexes under /apex.
Result<void> ParseRcScriptsFromAllApexes(bool bootstrap);

}  // namespace init
}  // namespace android
