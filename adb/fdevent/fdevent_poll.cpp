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

#define TRACE_TAG FDEVENT

#include "sysdeps.h"
#include "fdevent_poll.h"

#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <atomic>
#include <deque>
#include <functional>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/threads.h>

#include "adb_io.h"
#include "adb_trace.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "fdevent.h"
#include "sysdeps/chrono.h"

static void fdevent_interrupt(int fd, unsigned, void*) {
    char buf[BUFSIZ];
    ssize_t rc = TEMP_FAILURE_RETRY(adb_read(fd, buf, sizeof(buf)));
    if (rc == -1) {
        PLOG(FATAL) << "failed to read from fdevent interrupt fd";
    }
}

fdevent_context_poll::fdevent_context_poll() {
    int s[2];
    if (adb_socketpair(s) != 0) {
        PLOG(FATAL) << "failed to create fdevent interrupt socketpair";
    }

    if (!set_file_block_mode(s[0], false) || !set_file_block_mode(s[1], false)) {
        PLOG(FATAL) << "failed to make fdevent interrupt socket nonblocking";
    }

    this->interrupt_fd_.reset(s[0]);
    fdevent* fde = this->Create(unique_fd(s[1]), fdevent_interrupt, nullptr);
    CHECK(fde != nullptr);
    this->Add(fde, FDE_READ);
}

fdevent_context_poll::~fdevent_context_poll() {
    // Destroy calls virtual methods, but this class is final, so that's okay.
    this->Destroy(this->interrupt_fde_);
}

void fdevent_context_poll::Set(fdevent* fde, unsigned events) {
    CheckMainThread();
    fde->state = events;
    D("fdevent_set: %s, events = %u", dump_fde(fde).c_str(), events);
}

static std::string dump_pollfds(const std::vector<adb_pollfd>& pollfds) {
    std::string result;
    for (const auto& pollfd : pollfds) {
        std::string op;
        if (pollfd.events & POLLIN) {
            op += "R";
        }
        if (pollfd.events & POLLOUT) {
            op += "W";
        }
        android::base::StringAppendF(&result, " %d(%s)", pollfd.fd, op.c_str());
    }
    return result;
}

void fdevent_context_poll::Loop() {
    main_thread_id_ = android::base::GetThreadId();

    std::vector<adb_pollfd> pollfds;
    std::vector<fdevent_event> poll_events;

    while (true) {
        if (terminate_loop_) {
            break;
        }

        D("--- --- waiting for events");
        pollfds.clear();
        for (const auto& [fd, fde] : this->installed_fdevents_) {
            adb_pollfd pfd;
            pfd.fd = fd;
            pfd.events = 0;
            if (fde.state & FDE_READ) {
                pfd.events |= POLLIN;
            }
            if (fde.state & FDE_WRITE) {
                pfd.events |= POLLOUT;
            }
            if (fde.state & FDE_ERROR) {
                pfd.events |= POLLERR;
            }
#if defined(__linux__)
            pfd.events |= POLLRDHUP;
#endif
            pfd.revents = 0;
            pollfds.push_back(pfd);
        }
        CHECK_GT(pollfds.size(), 0u);
        D("poll(), pollfds = %s", dump_pollfds(pollfds).c_str());

        std::optional<std::chrono::milliseconds> timeout = CalculatePollDuration();
        int timeout_ms;
        if (!timeout) {
            timeout_ms = -1;
        } else {
            timeout_ms = timeout->count();
        }

        int ret = adb_poll(pollfds.data(), pollfds.size(), timeout_ms);
        if (ret == -1) {
            PLOG(ERROR) << "poll(), ret = " << ret;
            return;
        }

        auto post_poll = std::chrono::steady_clock::now();

        for (const auto& pollfd : pollfds) {
            unsigned events = 0;
            if (pollfd.revents & POLLIN) {
                events |= FDE_READ;
            }
            if (pollfd.revents & POLLOUT) {
                events |= FDE_WRITE;
            }
            if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // We fake a read, as the rest of the code assumes that errors will
                // be detected at that point.
                events |= FDE_READ | FDE_ERROR;
            }
#if defined(__linux__)
            if (pollfd.revents & POLLRDHUP) {
                events |= FDE_READ | FDE_ERROR;
            }
#endif

            auto it = this->installed_fdevents_.find(pollfd.fd);
            CHECK(it != this->installed_fdevents_.end());
            fdevent* fde = &it->second;

            if (events == 0) {
                if (fde->timeout) {
                    auto deadline = fde->last_active + *fde->timeout;
                    if (deadline < post_poll) {
                        events |= FDE_TIMEOUT;
                    }
                }
            }

            if (events != 0) {
                D("%s got events %x", dump_fde(fde).c_str(), events);
                poll_events.push_back({fde, events});
                fde->last_active = post_poll;
            }
        }
        this->HandleEvents(poll_events);
        poll_events.clear();
    }

    main_thread_id_.reset();
}

size_t fdevent_context_poll::InstalledCount() {
    // We always have an installed fde for interrupt.
    return this->installed_fdevents_.size() - 1;
}

void fdevent_context_poll::Interrupt() {
    int rc = adb_write(this->interrupt_fd_, "", 1);

    // It's possible that we get EAGAIN here, if lots of notifications came in while handling.
    if (rc == 0) {
        PLOG(FATAL) << "fdevent interrupt fd was closed?";
    } else if (rc == -1 && errno != EAGAIN) {
        PLOG(FATAL) << "failed to write to fdevent interrupt fd";
    }
}
