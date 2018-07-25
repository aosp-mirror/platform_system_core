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

#ifndef _INIT_EPOLL_H
#define _INIT_EPOLL_H

#include <chrono>
#include <functional>
#include <map>
#include <optional>

#include <android-base/unique_fd.h>

#include "result.h"

namespace android {
namespace init {

class Epoll {
  public:
    Epoll();

    Result<Success> Open();
    Result<Success> RegisterHandler(int fd, std::function<void()> handler);
    Result<Success> UnregisterHandler(int fd);
    Result<Success> Wait(std::optional<std::chrono::milliseconds> timeout);

  private:
    android::base::unique_fd epoll_fd_;
    std::map<int, std::function<void()>> epoll_handlers_;
};

}  // namespace init
}  // namespace android

#endif
