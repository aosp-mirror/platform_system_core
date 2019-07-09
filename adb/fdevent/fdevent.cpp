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

#include "fdevent.h"
#include "fdevent_poll.h"

std::string dump_fde(const fdevent* fde) {
    std::string state;
    if (fde->state & FDE_ACTIVE) {
        state += "A";
    }
    if (fde->state & FDE_PENDING) {
        state += "P";
    }
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
            fn = this->run_queue_.front();
            this->run_queue_.pop_front();
        }
        fn();
    }
}

static auto& g_ambient_fdevent_context =
        *new std::unique_ptr<fdevent_context>(new fdevent_context_poll());

static fdevent_context* fdevent_get_ambient() {
    return g_ambient_fdevent_context.get();
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
    g_ambient_fdevent_context.reset(new fdevent_context_poll());
}
