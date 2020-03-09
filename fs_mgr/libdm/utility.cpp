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

#include "utility.h"

#include <errno.h>
#include <unistd.h>

#include <thread>

#include <android-base/logging.h>

using namespace std::literals;

namespace android {
namespace dm {

bool WaitForCondition(const std::function<WaitResult()>& condition,
                      const std::chrono::milliseconds& timeout_ms) {
    auto start_time = std::chrono::steady_clock::now();
    while (true) {
        auto result = condition();
        if (result == WaitResult::Done) return true;
        if (result == WaitResult::Fail) return false;

        std::this_thread::sleep_for(20ms);

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (time_elapsed > timeout_ms) return false;
    }
}

bool WaitForFile(const std::string& path, const std::chrono::milliseconds& timeout_ms) {
    auto condition = [&]() -> WaitResult {
        // If the file exists but returns EPERM or something, we consider the
        // condition met.
        if (access(path.c_str(), F_OK) != 0) {
            if (errno == ENOENT) {
                return WaitResult::Wait;
            }
            PLOG(ERROR) << "access failed: " << path;
            return WaitResult::Fail;
        }
        return WaitResult::Done;
    };
    return WaitForCondition(condition, timeout_ms);
}

bool WaitForFileDeleted(const std::string& path, const std::chrono::milliseconds& timeout_ms) {
    auto condition = [&]() -> WaitResult {
        if (access(path.c_str(), F_OK) == 0) {
            return WaitResult::Wait;
        }
        if (errno != ENOENT) {
            PLOG(ERROR) << "access failed: " << path;
            return WaitResult::Fail;
        }
        return WaitResult::Done;
    };
    return WaitForCondition(condition, timeout_ms);
}

}  // namespace dm
}  // namespace android
