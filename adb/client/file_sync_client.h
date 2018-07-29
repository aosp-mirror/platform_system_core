/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <string>
#include <vector>

bool do_sync_ls(const char* path);
bool do_sync_push(const std::vector<const char*>& srcs, const char* dst, bool sync);
bool do_sync_pull(const std::vector<const char*>& srcs, const char* dst, bool copy_attrs,
                  const char* name = nullptr);

bool do_sync_sync(const std::string& lpath, const std::string& rpath, bool list_only);
