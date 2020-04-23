/*
 * Copyright 2006, Brian Swetland <swetland@frotz.net>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define TRACE_TAG FDEVENT

#include "sysdeps.h"

#include <inttypes.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/threads.h>

#include "adb_utils.h"
#include "fdevent.h"
#include "fdevent_epoll.h"
#include "fdevent_poll.h"

using namespace std::chrono_literals;
using std::chrono::duration_cast;

void invoke_fde(struct fdevent* fde, unsigned events) {
    if (auto f = std::get_if<fd_func>(&fde->func)) {
        (*f)(fde->fd.get(), events, fde->arg);
    } else if (auto f = std::get_if<fd_func2>(&fde->func)) {
        (*f)(fde, events, fde->arg);
    } else {
        __builtin_unreachable();
    }
}

std::string dump_fde(const fdevent* fde) {
    std::string state;
    if (fde->state & FDE_READ) {
        state += "R";
    }
    if (fde->state & FDE_WRITE) {
        state += "W";
    }
    if (fde->state & FDE_ERROR) {
        state += "E";
    }
    return android::base::StringPrintf("(fdevent %" PRIu64 ": fd %d %s)", fde->id, fde->fd.get(),
                                       state.c_str());
}

fdevent* fdevent_context::Create(unique_fd fd, std::variant<fd_func, fd_func2> func, void* arg) {
    CheckMainThread();
    CHECK_GE(fd.get(), 0);

    int fd_num = fd.get();

    auto [it, inserted] = this->installed_fdevents_.emplace(fd_num, fdevent{});
    CHECK(inserted);

    fdevent* fde = &it->second;
    fde->id = fdevent_id_++;
    fde->state = 0;
    fde->fd = std::move(fd);
    fde->func = func;
    fde->arg = arg;
    if (!set_file_block_mode(fde->fd, false)) {
        // Here is not proper to handle the error. If it fails here, some error is
        // likely to be detected by poll(), then we can let the callback function
        // to handle it.
        LOG(ERROR) << "failed to set non-blocking mode for fd " << fde->fd.get();
    }

    this->Register(fde);
    return fde;
}

unique_fd fdevent_context::Destroy(fdevent* fde) {
    CheckMainThread();
    if (!fde) {
        return {};
    }

    this->Unregister(fde);

    unique_fd fd = std::move(fde->fd);

    auto erased = this->installed_fdevents_.erase(fd.get());
    CHECK_EQ(1UL, erased);

    return fd;
}

void fdevent_context::Add(fdevent* fde, unsigned events) {
    CHECK(!(events & FDE_TIMEOUT));
    Set(fde, fde->state | events);
}

void fdevent_context::Del(fdevent* fde, unsigned events) {
    CHECK(!(events & FDE_TIMEOUT));
    Set(fde, fde->state & ~events);
}

void fdevent_context::SetTimeout(fdevent* fde, std::optional<std::chrono::milliseconds> timeout) {
    CheckMainThread();
    fde->timeout = timeout;
    fde->last_active = std::chrono::steady_clock::now();
}

std::optional<std::chrono::milliseconds> fdevent_context::CalculatePollDuration() {
    std::optional<std::chrono::milliseconds> result = std::nullopt;
    auto now = std::chrono::steady_clock::now();
    CheckMainThread();

    for (const auto& [fd, fde] : this->installed_fdevents_) {
        UNUSED(fd);
        auto timeout_opt = fde.timeout;
        if (timeout_opt) {
            auto deadline = fde.last_active + *timeout_opt;
            auto time_left = duration_cast<std::chrono::milliseconds>(deadline - now);
            if (time_left < 0ms) {
                time_left = 0ms;
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

void fdevent_context::HandleEvents(const std::vector<fdevent_event>& events) {
    for (const auto& event : events) {
        invoke_fde(event.fde, event.events);
    }
    FlushRunQueue();
}

void fdevent_context::FlushRunQueue() {
    // We need to be careful around reentrancy here, since a function we call can queue up another
    // function.
    while (true) {
        std::function<void()> fn;
        {
            std::lock_guard<std::mutex> lock(this->run_queue_mutex_);
            if (this->run_queue_.empty()) {
                break;
            }
            fn = std::move(this->run_queue_.front());
            this->run_queue_.pop_front();
        }
        fn();
    }
}

void fdevent_context::CheckMainThread() {
    if (main_thread_id_) {
        CHECK_EQ(*main_thread_id_, android::base::GetThreadId());
    }
}

void fdevent_context::Run(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lock(run_queue_mutex_);
        run_queue_.push_back(std::move(fn));
    }

    Interrupt();
}

void fdevent_context::TerminateLoop() {
    terminate_loop_ = true;
    Interrupt();
}

static std::unique_ptr<fdevent_context> fdevent_create_context() {
#if defined(__linux__)
    return std::make_unique<fdevent_context_epoll>();
#else
    return std::make_unique<fdevent_context_poll>();
#endif
}

static auto& g_ambient_fdevent_context() {
    static auto context = fdevent_create_context().release();
    return context;
}

static fdevent_context* fdevent_get_ambient() {
    return g_ambient_fdevent_context();
}

fdevent* fdevent_create(int fd, fd_func func, void* arg) {
    unique_fd ufd(fd);
    return fdevent_get_ambient()->Create(std::move(ufd), func, arg);
}

fdevent* fdevent_create(int fd, fd_func2 func, void* arg) {
    unique_fd ufd(fd);
    return fdevent_get_ambient()->Create(std::move(ufd), func, arg);
}

unique_fd fdevent_release(fdevent* fde) {
    return fdevent_get_ambient()->Destroy(fde);
}

void fdevent_destroy(fdevent* fde) {
    fdevent_get_ambient()->Destroy(fde);
}

void fdevent_set(fdevent* fde, unsigned events) {
    fdevent_get_ambient()->Set(fde, events);
}

void fdevent_add(fdevent* fde, unsigned events) {
    fdevent_get_ambient()->Add(fde, events);
}

void fdevent_del(fdevent* fde, unsigned events) {
    fdevent_get_ambient()->Del(fde, events);
}

void fdevent_set_timeout(fdevent* fde, std::optional<std::chrono::milliseconds> timeout) {
    fdevent_get_ambient()->SetTimeout(fde, timeout);
}

void fdevent_run_on_main_thread(std::function<void()> fn) {
    fdevent_get_ambient()->Run(std::move(fn));
}

void fdevent_loop() {
    fdevent_get_ambient()->Loop();
}

void check_main_thread() {
    fdevent_get_ambient()->CheckMainThread();
}

void fdevent_terminate_loop() {
    fdevent_get_ambient()->TerminateLoop();
}

size_t fdevent_installed_count() {
    return fdevent_get_ambient()->InstalledCount();
}

void fdevent_reset() {
    auto old = std::exchange(g_ambient_fdevent_context(), fdevent_create_context().release());
    delete old;
}
