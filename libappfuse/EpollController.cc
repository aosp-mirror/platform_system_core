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

#include <android-base/logging.h>

#include "libappfuse/EpollController.h"

namespace android {
namespace fuse {

EpollController::EpollController(base::unique_fd&& poll_fd) : poll_fd_(std::move(poll_fd)) {
}

bool EpollController::Wait(size_t event_count) {
    events_.resize(event_count);
    const int result = TEMP_FAILURE_RETRY(epoll_wait(poll_fd_, events_.data(), event_count, -1));
    if (result == -1) {
        PLOG(ERROR) << "Failed to wait for epoll";
        return false;
    }
    events_.resize(result);
    return true;
}

bool EpollController::AddFd(int fd, int events, void* data) {
    return InvokeControl(EPOLL_CTL_ADD, fd, events, data);
}

bool EpollController::UpdateFd(int fd, int events, void* data) {
    return InvokeControl(EPOLL_CTL_MOD, fd, events, data);
}

bool EpollController::RemoveFd(int fd) {
    return InvokeControl(EPOLL_CTL_DEL, fd, /* events */ 0, nullptr);
}

const std::vector<epoll_event>& EpollController::events() const {
    return events_;
}

bool EpollController::InvokeControl(int op, int fd, int events, void* data) const {
    epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = events;
    event.data.ptr = data;
    if (epoll_ctl(poll_fd_, op, fd, &event) == -1) {
        PLOG(ERROR) << "epoll_ctl() error op=" << op;
        return false;
    }
    return true;
}
}
}
