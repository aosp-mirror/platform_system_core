/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "fdevent_epoll.h"

#if defined(__linux__)

#include <sys/epoll.h>
#include <sys/eventfd.h>

#include <android-base/logging.h>
#include <android-base/threads.h>

#include "adb_unique_fd.h"
#include "fdevent.h"

static void fdevent_interrupt(int fd, unsigned, void*) {
    uint64_t buf;
    ssize_t rc = TEMP_FAILURE_RETRY(adb_read(fd, &buf, sizeof(buf)));
    if (rc == -1) {
        PLOG(FATAL) << "failed to read from fdevent interrupt fd";
    }
}

fdevent_context_epoll::fdevent_context_epoll() {
    epoll_fd_.reset(epoll_create1(EPOLL_CLOEXEC));

    unique_fd interrupt_fd(eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK));
    if (interrupt_fd == -1) {
        PLOG(FATAL) << "failed to create fdevent interrupt eventfd";
    }

    unique_fd interrupt_fd_dup(fcntl(interrupt_fd.get(), F_DUPFD_CLOEXEC, 3));
    if (interrupt_fd_dup == -1) {
        PLOG(FATAL) << "failed to dup fdevent interrupt eventfd";
    }

    this->interrupt_fd_ = std::move(interrupt_fd_dup);
    fdevent* fde = this->Create(std::move(interrupt_fd), fdevent_interrupt, nullptr);
    CHECK(fde != nullptr);
    this->Add(fde, FDE_READ);
}

fdevent_context_epoll::~fdevent_context_epoll() {
    // Destroy calls virtual methods, but this class is final, so that's okay.
    this->Destroy(this->interrupt_fde_);
}

static epoll_event calculate_epoll_event(fdevent* fde) {
    epoll_event result;
    result.events = 0;
    if (fde->state & FDE_READ) {
        result.events |= EPOLLIN;
    }
    if (fde->state & FDE_WRITE) {
        result.events |= EPOLLOUT;
    }
    if (fde->state & FDE_ERROR) {
        result.events |= EPOLLERR;
    }
    result.events |= EPOLLRDHUP;
    result.data.ptr = fde;
    return result;
}

void fdevent_context_epoll::Register(fdevent* fde) {
    epoll_event ev = calculate_epoll_event(fde);
    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_ADD, fde->fd.get(), &ev) != 0) {
        PLOG(FATAL) << "failed to register fd " << fde->fd.get() << " with epoll";
    }
}

void fdevent_context_epoll::Unregister(fdevent* fde) {
    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_DEL, fde->fd.get(), nullptr) != 0) {
        PLOG(FATAL) << "failed to unregister fd " << fde->fd.get() << " with epoll";
    }
}

void fdevent_context_epoll::Set(fdevent* fde, unsigned events) {
    unsigned previous_state = fde->state;
    fde->state = events;

    // If the state is the same, or only differed by FDE_TIMEOUT, we don't need to modify epoll.
    if ((previous_state & ~FDE_TIMEOUT) == (events & ~FDE_TIMEOUT)) {
        return;
    }

    epoll_event ev = calculate_epoll_event(fde);
    if (epoll_ctl(epoll_fd_.get(), EPOLL_CTL_MOD, fde->fd.get(), &ev) != 0) {
        PLOG(FATAL) << "failed to modify fd " << fde->fd.get() << " with epoll";
    }
}

void fdevent_context_epoll::Loop() {
    main_thread_id_ = android::base::GetThreadId();

    std::vector<fdevent_event> fde_events;
    std::vector<epoll_event> epoll_events;
    epoll_events.resize(this->installed_fdevents_.size());

    while (true) {
        if (terminate_loop_) {
            break;
        }

        int rc = -1;
        while (rc == -1) {
            std::optional<std::chrono::milliseconds> timeout = CalculatePollDuration();
            int timeout_ms;
            if (!timeout) {
                timeout_ms = -1;
            } else {
                timeout_ms = timeout->count();
            }

            rc = epoll_wait(epoll_fd_.get(), epoll_events.data(), epoll_events.size(), timeout_ms);
            if (rc == -1 && errno != EINTR) {
                PLOG(FATAL) << "epoll_wait failed";
            }
        }

        auto post_poll = std::chrono::steady_clock::now();
        std::unordered_map<fdevent*, unsigned> event_map;
        for (int i = 0; i < rc; ++i) {
            fdevent* fde = static_cast<fdevent*>(epoll_events[i].data.ptr);

            unsigned events = 0;
            if (epoll_events[i].events & EPOLLIN) {
                CHECK(fde->state & FDE_READ);
                events |= FDE_READ;
            }
            if (epoll_events[i].events & EPOLLOUT) {
                CHECK(fde->state & FDE_WRITE);
                events |= FDE_WRITE;
            }
            if (epoll_events[i].events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                // We fake a read, as the rest of the code assumes that errors will
                // be detected at that point.
                events |= FDE_READ | FDE_ERROR;
            }

            event_map[fde] = events;
        }

        for (auto& [fd, fde] : installed_fdevents_) {
            unsigned events = 0;
            if (auto it = event_map.find(&fde); it != event_map.end()) {
                events = it->second;
            }

            if (events == 0) {
                if (fde.timeout) {
                    auto deadline = fde.last_active + *fde.timeout;
                    if (deadline < post_poll) {
                        events |= FDE_TIMEOUT;
                    }
                }
            }

            if (events != 0) {
                LOG(DEBUG) << dump_fde(&fde) << " got events " << std::hex << std::showbase
                           << events;
                fde_events.push_back({&fde, events});
                fde.last_active = post_poll;
            }
        }
        this->HandleEvents(fde_events);
        fde_events.clear();
    }

    main_thread_id_.reset();
}

size_t fdevent_context_epoll::InstalledCount() {
    // We always have an installed fde for interrupt.
    return this->installed_fdevents_.size() - 1;
}

void fdevent_context_epoll::Interrupt() {
    uint64_t i = 1;
    ssize_t rc = TEMP_FAILURE_RETRY(adb_write(this->interrupt_fd_, &i, sizeof(i)));
    if (rc != sizeof(i)) {
        PLOG(FATAL) << "failed to write to fdevent interrupt eventfd";
    }
}

#endif  // defined(__linux__)
