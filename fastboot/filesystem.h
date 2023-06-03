/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/unique_fd.h>

#include <string>

using android::base::unique_fd;

// TODO(b/175635923): remove after enabling libc++fs for windows
const char kPathSeparator =
#ifdef _WIN32
        '\\';
#else
        '/';
#endif

std::string GetHomeDirPath();
bool FileExists(const std::string& path);
bool EnsureDirectoryExists(const std::string& directory_path);

class FileLock {
  public:
    FileLock() = delete;
    FileLock(const std::string& path);

  private:
    unique_fd fd_;
};