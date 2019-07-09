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

void fdevent_context_poll::CheckMainThread() {
    if (main_thread_valid_) {
        CHECK_EQ(main_thread_id_, android::base::GetThreadId());
    }
}

fdevent* fdevent_context_poll::Create(unique_fd fd, std::variant<fd_func, fd_func2> func,
                                      void* arg) {
    CheckMainThread();
    CHECK_GE(fd.get(), 0);

    fdevent* fde = new fdevent();
    fde->id = fdevent_id_++;
    fde->state = FDE_ACTIVE;
    fde->fd = std::move(fd);
    fde->func = func;
    fde->arg = arg;
    if (!set_file_block_mode(fde->fd, false)) {
        // Here is not proper to handle the error. If it fails here, some error is
        // likely to be detected by poll(), then we can let the callback function
        // to handle it.
        LOG(ERROR) << "failed to set non-blocking mode for fd " << fde->fd.get();
    }
    auto pair = poll_node_map_.emplace(fde->fd.get(), PollNode(fde));
    CHECK(pair.second) << "install existing fd " << fde->fd.get();

    fde->state |= FDE_CREATED;
    return fde;
}

unique_fd fdevent_context_poll::Destroy(fdevent* fde) {
    CheckMainThread();
    if (!fde) {
        return {};
    }

    if (!(fde->state & FDE_CREATED)) {
        LOG(FATAL) << "destroying fde not created by fdevent_create(): " << dump_fde(fde);
    }

    unique_fd result = std::move(fde->fd);
    if (fde->state & FDE_ACTIVE) {
        poll_node_map_.erase(result.get());

        if (fde->state & FDE_PENDING) {
            pending_list_.remove(fde);
        }
        fde->state = 0;
        fde->events = 0;
    }

    delete fde;
    return result;
}

void fdevent_context_poll::Set(fdevent* fde, unsigned events) {
    CheckMainThread();
    events &= FDE_EVENTMASK;
    if ((fde->state & FDE_EVENTMASK) == events) {
        return;
    }
    CHECK(fde->state & FDE_ACTIVE);

    auto it = poll_node_map_.find(fde->fd.get());
    CHECK(it != poll_node_map_.end());
    PollNode& node = it->second;
    if (events & FDE_READ) {
        node.pollfd.events |= POLLIN;
    } else {
        node.pollfd.events &= ~POLLIN;
    }

    if (events & FDE_WRITE) {
        node.pollfd.events |= POLLOUT;
    } else {
        node.pollfd.events &= ~POLLOUT;
    }
    fde->state = (fde->state & FDE_STATEMASK) | events;

    D("fdevent_set: %s, events = %u", dump_fde(fde).c_str(), events);

    if (fde->state & FDE_PENDING) {
        // If we are pending, make sure we don't signal an event that is no longer wanted.
        fde->events &= events;
        if (fde->events == 0) {
            pending_list_.remove(fde);
            fde->state &= ~FDE_PENDING;
        }
    }
}

void fdevent_context_poll::Add(fdevent* fde, unsigned events) {
    Set(fde, (fde->state & FDE_EVENTMASK) | events);
}

void fdevent_context_poll::Del(fdevent* fde, unsigned events) {
    CHECK(!(events & FDE_TIMEOUT));
    Set(fde, (fde->state & FDE_EVENTMASK) & ~events);
}

void fdevent_context_poll::SetTimeout(fdevent* fde,
                                      std::optional<std::chrono::milliseconds> timeout) {
    CheckMainThread();
    fde->timeout = timeout;
    fde->last_active = std::chrono::steady_clock::now();
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

static std::optional<std::chrono::milliseconds> calculate_timeout(fdevent_context_poll* ctx) {
    std::optional<std::chrono::milliseconds> result = std::nullopt;
    auto now = std::chrono::steady_clock::now();
    ctx->CheckMainThread();

    for (const auto& [fd, pollnode] : ctx->poll_node_map_) {
        UNUSED(fd);
        auto timeout_opt = pollnode.fde->timeout;
        if (timeout_opt) {
            auto deadline = pollnode.fde->last_active + *timeout_opt;
            auto time_left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
            if (time_left < std::chrono::milliseconds::zero()) {
                time_left = std::chrono::milliseconds::zero();
            }

            if (!result) {
                result = time_left;
            } else {
                result = std::min(*result, time_left);
            }
        }
    }

    return result;
}

static void fdevent_process(fdevent_context_poll* ctx) {
    std::vector<adb_pollfd> pollfds;
    for (const auto& pair : ctx->poll_node_map_) {
        pollfds.push_back(pair.second.pollfd);
    }
    CHECK_GT(pollfds.size(), 0u);
    D("poll(), pollfds = %s", dump_pollfds(pollfds).c_str());

    auto timeout = calculate_timeout(ctx);
    int timeout_ms;
    if (!timeout) {
        timeout_ms = -1;
    } else {
        timeout_ms = timeout->count();
    }

    int ret = adb_poll(&pollfds[0], pollfds.size(), timeout_ms);
    if (ret == -1) {
        PLOG(ERROR) << "poll(), ret = " << ret;
        return;
    }

    auto post_poll = std::chrono::steady_clock::now();

    for (const auto& pollfd : pollfds) {
        if (pollfd.revents != 0) {
            D("for fd %d, revents = %x", pollfd.fd, pollfd.revents);
        }
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
        auto it = ctx->poll_node_map_.find(pollfd.fd);
        CHECK(it != ctx->poll_node_map_.end());
        fdevent* fde = it->second.fde;

        if (events == 0) {
            // Check for timeout.
            if (fde->timeout) {
                auto deadline = fde->last_active + *fde->timeout;
                if (deadline < post_poll) {
                    events |= FDE_TIMEOUT;
                }
            }
        }

        if (events != 0) {
            CHECK_EQ(fde->fd.get(), pollfd.fd);
            fde->events |= events;
            fde->last_active = post_poll;
            D("%s got events %x", dump_fde(fde).c_str(), events);
            fde->state |= FDE_PENDING;
            ctx->pending_list_.push_back(fde);
        }
    }
}

template <class T>
struct always_false : std::false_type {};

static void fdevent_call_fdfunc(fdevent* fde) {
    unsigned events = fde->events;
    fde->events = 0;
    CHECK(fde->state & FDE_PENDING);
    fde->state &= (~FDE_PENDING);
    D("fdevent_call_fdfunc %s", dump_fde(fde).c_str());
    std::visit(
            [&](auto&& f) {
                using F = std::decay_t<decltype(f)>;
                if constexpr (std::is_same_v<fd_func, F>) {
                    f(fde->fd.get(), events, fde->arg);
                } else if constexpr (std::is_same_v<fd_func2, F>) {
                    f(fde, events, fde->arg);
                } else {
                    static_assert(always_false<F>::value, "non-exhaustive visitor");
                }
            },
            fde->func);
}

static void fdevent_run_flush(fdevent_context_poll* ctx) EXCLUDES(ctx->run_queue_mutex_) {
    // We need to be careful around reentrancy here, since a function we call can queue up another
    // function.
    while (true) {
        std::function<void()> fn;
        {
            std::lock_guard<std::mutex> lock(ctx->run_queue_mutex_);
            if (ctx->run_queue_.empty()) {
                break;
            }
            fn = ctx->run_queue_.front();
            ctx->run_queue_.pop_front();
        }
        fn();
    }
}

static void fdevent_run_func(int fd, unsigned ev, void* data) {
    CHECK_GE(fd, 0);
    CHECK(ev & FDE_READ);

    bool* run_needs_flush = static_cast<bool*>(data);
    char buf[1024];

    // Empty the fd.
    if (adb_read(fd, buf, sizeof(buf)) == -1) {
        PLOG(FATAL) << "failed to empty run queue notify fd";
    }

    // Mark that we need to flush, and then run it at the end of fdevent_loop.
    *run_needs_flush = true;
}

static void fdevent_run_setup(fdevent_context_poll* ctx) {
    {
        std::lock_guard<std::mutex> lock(ctx->run_queue_mutex_);
        CHECK(ctx->run_queue_notify_fd_.get() == -1);
        int s[2];
        if (adb_socketpair(s) != 0) {
            PLOG(FATAL) << "failed to create run queue notify socketpair";
        }

        if (!set_file_block_mode(s[0], false) || !set_file_block_mode(s[1], false)) {
            PLOG(FATAL) << "failed to make run queue notify socket nonblocking";
        }

        ctx->run_queue_notify_fd_.reset(s[0]);
        fdevent* fde = ctx->Create(unique_fd(s[1]), fdevent_run_func, &ctx->run_needs_flush_);
        CHECK(fde != nullptr);
        ctx->Add(fde, FDE_READ);
    }

    fdevent_run_flush(ctx);
}

void fdevent_context_poll::Run(std::function<void()> fn) {
    std::lock_guard<std::mutex> lock(run_queue_mutex_);
    run_queue_.push_back(std::move(fn));

    // run_queue_notify_fd could still be -1 if we're called before fdevent has finished setting up.
    // In that case, rely on the setup code to flush the queue without a notification being needed.
    if (run_queue_notify_fd_ != -1) {
        int rc = adb_write(run_queue_notify_fd_.get(), "", 1);

        // It's possible that we get EAGAIN here, if lots of notifications came in while handling.
        if (rc == 0) {
            PLOG(FATAL) << "run queue notify fd was closed?";
        } else if (rc == -1 && errno != EAGAIN) {
            PLOG(FATAL) << "failed to write to run queue notify fd";
        }
    }
}

static void fdevent_check_spin(fdevent_context_poll* ctx, uint64_t cycle) {
    // Check to see if we're spinning because we forgot about an fdevent
    // by keeping track of how long fdevents have been continuously pending.
    struct SpinCheck {
        fdevent* fde;
        android::base::boot_clock::time_point timestamp;
        uint64_t cycle;
    };

    // TODO: Move this into the base fdevent_context.
    static auto& g_continuously_pending = *new std::unordered_map<uint64_t, SpinCheck>();
    static auto last_cycle = android::base::boot_clock::now();

    auto now = android::base::boot_clock::now();
    if (now - last_cycle > 10ms) {
        // We're not spinning.
        g_continuously_pending.clear();
        last_cycle = now;
        return;
    }
    last_cycle = now;

    for (auto* fde : ctx->pending_list_) {
        auto it = g_continuously_pending.find(fde->id);
        if (it == g_continuously_pending.end()) {
            g_continuously_pending[fde->id] =
                    SpinCheck{.fde = fde, .timestamp = now, .cycle = cycle};
        } else {
            it->second.cycle = cycle;
        }
    }

    for (auto it = g_continuously_pending.begin(); it != g_continuously_pending.end();) {
        if (it->second.cycle != cycle) {
            it = g_continuously_pending.erase(it);
        } else {
            // Use an absurdly long window, since all we really care about is
            // getting a bugreport eventually.
            if (now - it->second.timestamp > 300s) {
                LOG(FATAL_WITHOUT_ABORT)
                        << "detected spin in fdevent: " << dump_fde(it->second.fde);
#if defined(__linux__)
                int fd = it->second.fde->fd.get();
                std::string fd_path = android::base::StringPrintf("/proc/self/fd/%d", fd);
                std::string path;
                if (!android::base::Readlink(fd_path, &path)) {
                    PLOG(FATAL_WITHOUT_ABORT) << "readlink of fd " << fd << " failed";
                }
                LOG(FATAL_WITHOUT_ABORT) << "fd " << fd << " = " << path;
#endif
                abort();
            }
            ++it;
        }
    }
}

void fdevent_context_poll::Loop() {
    this->main_thread_id_ = android::base::GetThreadId();
    this->main_thread_valid_ = true;
    fdevent_run_setup(this);

    uint64_t cycle = 0;
    while (true) {
        if (terminate_loop_) {
            return;
        }

        D("--- --- waiting for events");

        fdevent_process(this);

        fdevent_check_spin(this, cycle++);

        while (!pending_list_.empty()) {
            fdevent* fde = pending_list_.front();
            pending_list_.pop_front();
            fdevent_call_fdfunc(fde);
        }

        if (run_needs_flush_) {
            fdevent_run_flush(this);
            run_needs_flush_ = false;
        }
    }
}

void fdevent_context_poll::TerminateLoop() {
    terminate_loop_ = true;
}

size_t fdevent_context_poll::InstalledCount() {
    return poll_node_map_.size();
}

void fdevent_context_poll::Reset() {
    poll_node_map_.clear();
    pending_list_.clear();

    std::lock_guard<std::mutex> lock(run_queue_mutex_);
    run_queue_notify_fd_.reset();
    run_queue_.clear();

    main_thread_valid_ = false;
    terminate_loop_ = false;
}
