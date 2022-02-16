// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <chrono>
#include <string>

namespace android {
namespace fs_mgr {

// Wait at most |relative_timeout| milliseconds for |path| to exist. dirname(path)
// must already exist. For example, to wait on /dev/block/dm-6, /dev/block must
// be a valid directory.
bool WaitForFile(const std::string& path, const std::chrono::milliseconds relative_timeout);

// Wait at most |relative_timeout| milliseconds for |path| to stop existing.
// Note that this only returns true if the inode itself no longer exists, i.e.,
// all outstanding file descriptors have been closed.
bool WaitForFileDeleted(const std::string& path, const std::chrono::milliseconds relative_timeout);

}  // namespace fs_mgr
}  // namespace android
