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
 * See the License for the specic language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_LIBAPPFUSE_EPOLLCONTROLLER_H_
#define ANDROID_LIBAPPFUSE_EPOLLCONTROLLER_H_

#include <sys/epoll.h>

#include <vector>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>

namespace android {
namespace fuse {

class EpollController {
  public:
    explicit EpollController(base::unique_fd&& poll_fd);
    bool Wait(size_t event_count);
    bool AddFd(int fd, int events, void* data);
    bool UpdateFd(int fd, int events, void* data);
    bool RemoveFd(int fd);

    const std::vector<epoll_event>& events() const;

  protected:
    bool InvokeControl(int op, int fd, int events, void* data) const;

  private:
    base::unique_fd poll_fd_;
    std::vector<epoll_event> events_;

    DISALLOW_COPY_AND_ASSIGN(EpollController);
};
}
}

#endif  // ANDROID_LIBAPPFUSE_EPOLLCONTROLLER_H_
