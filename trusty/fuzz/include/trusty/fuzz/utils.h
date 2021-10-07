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

#include <string>

#include <android-base/result.h>
#include <android-base/unique_fd.h>

#define TIPC_MAX_MSG_SIZE PAGE_SIZE

namespace android {
namespace trusty {
namespace fuzz {

class TrustyApp {
  public:
    TrustyApp(std::string tipc_dev, std::string ta_port);

    android::base::Result<void> Connect();
    android::base::Result<void> Read(void* buf, size_t len);
    android::base::Result<void> Write(const void* buf, size_t len);
    void Disconnect();

    android::base::Result<int> GetRawFd();

  private:
    std::string tipc_dev_;
    std::string ta_port_;
    android::base::unique_fd ta_fd_;
};

void Abort();

}  // namespace fuzz
}  // namespace trusty
}  // namespace android
