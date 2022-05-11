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

#include "epoll.h"

#include <stdint.h>
#include <sys/epoll.h>

#include <chrono>
#include <functional>
#include <map>

#include <android-base/logging.h>

namespace android {
namespace init {

Epoll::Epoll() {}

Result<void> Epoll::Open() {
    if (epoll_fd_ >= 0) return {};
    epoll_fd_.reset(epoll_create1(EPOLL_CLOEXEC));

    if (epoll_fd_ == -1) {
        return ErrnoError() << "epoll_create1 failed";
    }
    return {};
}

Result<void> Epoll::RegisterHandler(int fd, Handler handler, uint32_t events) {
    if (!events) {
        return Error() << "Must specify events";
    }

    Info info;
    info.events = events;
    info.handler = std::make_shared<decltype(handler)>(std::move(handler));
    auto [it, inserted] = epoll_handlers_.emplace(fd, std::move(info));
    if (!inserted) {
        return Error() << "Cannot specify two epoll handlers for a given FD";
    }
    epoll_event ev;
    ev.events = events;
    // std::map's iterators do not get invalidated until erased, so we use the
    // pointer to the std::function in the map directly for epoll_ctl.
    ev.data.ptr = reinterpret_cast<void*>(&it->second);
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) == -1) {
        Result<void> result = ErrnoError() << "epoll_ctl failed to add fd";
        epoll_handlers_.erase(fd);
        return result;
    }
    return {};
}

Result<void> Epoll::UnregisterHandler(int fd) {
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) == -1) {
        return ErrnoError() << "epoll_ctl failed to remove fd";
    }
    if (epoll_handlers_.erase(fd) != 1) {
        return Error() << "Attempting to remove epoll handler for FD without an existing handler";
    }
    return {};
}

Result<std::vector<std::shared_ptr<Epoll::Handler>>> Epoll::Wait(
        std::optional<std::chrono::milliseconds> timeout) {
    int timeout_ms = -1;
    if (timeout && timeout->count() < INT_MAX) {
        timeout_ms = timeout->count();
    }
    const auto max_events = epoll_handlers_.size();
    epoll_event ev[max_events];
    auto num_events = TEMP_FAILURE_RETRY(epoll_wait(epoll_fd_, ev, max_events, timeout_ms));
    if (num_events == -1) {
        return ErrnoError() << "epoll_wait failed";
    }
    std::vector<std::shared_ptr<Handler>> pending_functions;
    for (int i = 0; i < num_events; ++i) {
        auto& info = *reinterpret_cast<Info*>(ev[i].data.ptr);
        if ((info.events & (EPOLLIN | EPOLLPRI)) == (EPOLLIN | EPOLLPRI) &&
            (ev[i].events & EPOLLIN) != ev[i].events) {
            // This handler wants to know about exception events, and just got one.
            // Log something informational.
            LOG(ERROR) << "Received unexpected epoll event set: " << ev[i].events;
        }
        pending_functions.emplace_back(info.handler);
    }

    return pending_functions;
}

}  // namespace init
}  // namespace android
