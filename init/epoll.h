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

#include <stdint.h>
#include <sys/epoll.h>

#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <vector>

#include <android-base/unique_fd.h>

#include "result.h"

namespace android {
namespace init {

class Epoll {
  public:
    Epoll();

    typedef std::function<void()> Handler;

    Result<void> Open();
    Result<void> RegisterHandler(int fd, Handler handler, uint32_t events = EPOLLIN);
    Result<void> UnregisterHandler(int fd);
    Result<std::vector<std::shared_ptr<Handler>>> Wait(
            std::optional<std::chrono::milliseconds> timeout);

  private:
    struct Info {
        std::shared_ptr<Handler> handler;
        uint32_t events;
    };

    android::base::unique_fd epoll_fd_;
    std::map<int, Info> epoll_handlers_;
};

}  // namespace init
}  // namespace android
