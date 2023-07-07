/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "watchdog.h"

#include <chrono>
#include <cstdint>
#include <optional>
#include <thread>
#include <vector>

#include <android-base/logging.h>

struct watcher {
    watcher(const char* id, const struct storage_msg* request);
    void SetState(const char* new_state);
    void LogTimeout();
    void LogFinished();

    const char* id_;
    uint32_t cmd_;
    uint32_t op_id_;
    uint32_t flags_;
    const char* state_;

    using clock = std::chrono::high_resolution_clock;
    clock::time_point start_;
    clock::time_point state_change_;
    std::chrono::milliseconds Elapsed(clock::time_point end);

    bool triggered_;
};

watcher::watcher(const char* id, const struct storage_msg* request)
    : id_(id), state_(nullptr), triggered_(false) {
    cmd_ = request->cmd;
    op_id_ = request->op_id;
    flags_ = request->flags;

    start_ = clock::now();
    state_change_ = start_;
}

void watcher::SetState(const char* new_state) {
    state_ = new_state;
    state_change_ = clock::now();
}

void watcher::LogTimeout() {
    if (!triggered_) {
        triggered_ = true;
        LOG(ERROR) << "Storageproxyd watchdog triggered: " << id_ << " cmd: " << cmd_
                   << " op_id: " << op_id_ << " flags: " << flags_;
    }
    if (state_) {
        LOG(ERROR) << "...elapsed: " << Elapsed(clock::now()).count() << "ms (" << state_ << " "
                   << Elapsed(state_change_).count() << "ms)";
    } else {
        LOG(ERROR) << "...elapsed: " << Elapsed(clock::now()).count() << "ms";
    }
}

void watcher::LogFinished() {
    if (triggered_) {
        LOG(ERROR) << "...completed: " << Elapsed(clock::now()).count() << "ms";
    }
}

std::chrono::milliseconds watcher::Elapsed(watcher::clock::time_point end) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(end - start_);
}

namespace {

class Watchdog {
  private:
    static constexpr std::chrono::milliseconds kDefaultTimeoutMs = std::chrono::milliseconds(500);
    static constexpr std::chrono::milliseconds kMaxTimeoutMs = std::chrono::seconds(10);

  public:
    Watchdog() : watcher_(), done_(false) {}
    ~Watchdog();
    struct watcher* RegisterWatch(const char* id, const struct storage_msg* request);
    void AddProgress(struct watcher* watcher, const char* state);
    void UnRegisterWatch(struct watcher* watcher);

  private:
    // Syncronizes access to watcher_ and watcher_change_ between the main
    // thread and watchdog loop thread. watcher_ may only be modified by the
    // main thread; the watchdog loop is read-only.
    std::mutex watcher_mutex_;
    std::unique_ptr<struct watcher> watcher_;
    std::condition_variable watcher_change_;

    std::thread watchdog_thread_;
    bool done_;

    void WatchdogLoop();
    void LogWatchdogTriggerLocked();
};

Watchdog gWatchdog;

}  // Anonymous namespace

// Assumes that caller is single-threaded. If we want to use this from a
// multi-threaded context we need to ensure that the watchdog thread is
// initialized safely once and accessing an existing watcher is done while the
// watcher lock is held.
struct watcher* Watchdog::RegisterWatch(const char* id, const struct storage_msg* request) {
    if (!watchdog_thread_.joinable()) {
        watchdog_thread_ = std::thread(&Watchdog::WatchdogLoop, this);
    }
    if (watcher_) {
        LOG(ERROR) << "Replacing registered watcher " << watcher_->id_;
        UnRegisterWatch(watcher_.get());
    }

    struct watcher* ret = nullptr;
    {
        std::unique_lock<std::mutex> watcherLock(watcher_mutex_);
        watcher_ = std::make_unique<struct watcher>(id, request);
        ret = watcher_.get();
    }
    watcher_change_.notify_one();
    return ret;
}

void Watchdog::UnRegisterWatch(struct watcher* watcher) {
    {
        std::lock_guard<std::mutex> watcherLock(watcher_mutex_);
        if (!watcher_) {
            LOG(ERROR) << "Cannot unregister watcher, no watcher registered";
            return;
        }
        if (watcher_.get() != watcher) {
            LOG(ERROR) << "Unregistering watcher that doesn't match current watcher";
        }
        watcher_->LogFinished();
        watcher_.reset(nullptr);
    }
    watcher_change_.notify_one();
}

void Watchdog::AddProgress(struct watcher* watcher, const char* state) {
    std::lock_guard<std::mutex> watcherLock(watcher_mutex_);
    if (watcher_.get() != watcher) {
        LOG(ERROR) << "Watcher was not registered, cannot log progress: " << state;
        return;
    }
    watcher->SetState(state);
}

void Watchdog::WatchdogLoop() {
    std::unique_lock<std::mutex> lock(watcher_mutex_);
    std::chrono::milliseconds timeout = kDefaultTimeoutMs;

    while (!done_) {
        // wait for a watch to be registered
        watcher_change_.wait(lock, [this] { return !!watcher_; });

        // wait for the timeout or unregistration
        timeout = kDefaultTimeoutMs;
        do {
            if (!watcher_change_.wait_for(lock, timeout, [this] { return !watcher_; })) {
                watcher_->LogTimeout();
                timeout = std::min(timeout * 2, kMaxTimeoutMs);
            }
        } while (!!watcher_);
    }
}

Watchdog::~Watchdog() {
    {
        std::lock_guard<std::mutex> watcherLock(watcher_mutex_);
        watcher_.reset(nullptr);
        done_ = true;
    }
    watcher_change_.notify_one();
    if (watchdog_thread_.joinable()) {
        watchdog_thread_.join();
    }
}

struct watcher* watch_start(const char* id, const struct storage_msg* request) {
    return gWatchdog.RegisterWatch(id, request);
}

void watch_progress(struct watcher* watcher, const char* state) {
    gWatchdog.AddProgress(watcher, state);
}

void watch_finish(struct watcher* watcher) {
    gWatchdog.UnRegisterWatch(watcher);
}
