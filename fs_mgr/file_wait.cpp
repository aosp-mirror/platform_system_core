// Copyright (C) 2019 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fs_mgr/file_wait.h>

#include <limits.h>
#if defined(__linux__)
#include <poll.h>
#include <sys/inotify.h>
#endif
#if defined(WIN32)
#include <io.h>
#else
#include <unistd.h>
#endif

#include <functional>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>

namespace android {
namespace fs_mgr {

using namespace std::literals;
using android::base::unique_fd;

bool PollForFile(const std::string& path, const std::chrono::milliseconds relative_timeout) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        if (!access(path.c_str(), F_OK) || errno != ENOENT) return true;

        std::this_thread::sleep_for(50ms);

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (time_elapsed > relative_timeout) return false;
    }
}

bool PollForFileDeleted(const std::string& path, const std::chrono::milliseconds relative_timeout) {
    auto start_time = std::chrono::steady_clock::now();

    while (true) {
        if (access(path.c_str(), F_OK) && errno == ENOENT) return true;

        std::this_thread::sleep_for(50ms);

        auto now = std::chrono::steady_clock::now();
        auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time);
        if (time_elapsed > relative_timeout) return false;
    }
}

#if defined(__linux__)
class OneShotInotify {
  public:
    OneShotInotify(const std::string& path, uint32_t mask,
                   const std::chrono::milliseconds relative_timeout);

    bool Wait();

  private:
    bool CheckCompleted();
    int64_t RemainingMs() const;
    bool ConsumeEvents();

    enum class Result { Success, Timeout, Error };
    Result WaitImpl();

    unique_fd inotify_fd_;
    std::string path_;
    uint32_t mask_;
    std::chrono::time_point<std::chrono::steady_clock> start_time_;
    std::chrono::milliseconds relative_timeout_;
    bool finished_;
};

OneShotInotify::OneShotInotify(const std::string& path, uint32_t mask,
                               const std::chrono::milliseconds relative_timeout)
    : path_(path),
      mask_(mask),
      start_time_(std::chrono::steady_clock::now()),
      relative_timeout_(relative_timeout),
      finished_(false) {
    // If the condition is already met, don't bother creating an inotify.
    if (CheckCompleted()) return;

    unique_fd inotify_fd(inotify_init1(IN_CLOEXEC | IN_NONBLOCK));
    if (inotify_fd < 0) {
        PLOG(ERROR) << "inotify_init1 failed";
        return;
    }

    std::string watch_path;
    if (mask == IN_CREATE) {
        watch_path = android::base::Dirname(path);
    } else {
        watch_path = path;
    }
    if (inotify_add_watch(inotify_fd, watch_path.c_str(), mask) < 0) {
        PLOG(ERROR) << "inotify_add_watch failed";
        return;
    }

    // It's possible the condition was met before the add_watch. Check for
    // this and abort early if so.
    if (CheckCompleted()) return;

    inotify_fd_ = std::move(inotify_fd);
}

bool OneShotInotify::Wait() {
    Result result = WaitImpl();
    if (result == Result::Success) return true;
    if (result == Result::Timeout) return false;

    // Some kind of error with inotify occurred, so fallback to a poll.
    std::chrono::milliseconds timeout(RemainingMs());
    if (mask_ == IN_CREATE) {
        return PollForFile(path_, timeout);
    } else if (mask_ == IN_DELETE_SELF) {
        return PollForFileDeleted(path_, timeout);
    } else {
        LOG(ERROR) << "Unknown inotify mask: " << mask_;
        return false;
    }
}

OneShotInotify::Result OneShotInotify::WaitImpl() {
    // If the operation completed super early, we'll never have created an
    // inotify instance.
    if (finished_) return Result::Success;
    if (inotify_fd_ < 0) return Result::Error;

    while (true) {
        auto remaining_ms = RemainingMs();
        if (remaining_ms <= 0) return Result::Timeout;

        struct pollfd event = {
                .fd = inotify_fd_,
                .events = POLLIN,
                .revents = 0,
        };
        int rv = poll(&event, 1, static_cast<int>(remaining_ms));
        if (rv <= 0) {
            if (rv == 0 || errno == EINTR) {
                continue;
            }
            PLOG(ERROR) << "poll for inotify failed";
            return Result::Error;
        }
        if (event.revents & POLLERR) {
            LOG(ERROR) << "error reading inotify for " << path_;
            return Result::Error;
        }

        // Note that we don't bother checking what kind of event it is, since
        // it's cheap enough to just see if the initial condition is satisified.
        // If it's not, we consume all the events available and continue.
        if (CheckCompleted()) return Result::Success;
        if (!ConsumeEvents()) return Result::Error;
    }
}

bool OneShotInotify::CheckCompleted() {
    if (mask_ == IN_CREATE) {
        finished_ = !access(path_.c_str(), F_OK) || errno != ENOENT;
    } else if (mask_ == IN_DELETE_SELF) {
        finished_ = access(path_.c_str(), F_OK) && errno == ENOENT;
    } else {
        LOG(ERROR) << "Unexpected mask: " << mask_;
    }
    return finished_;
}

bool OneShotInotify::ConsumeEvents() {
    // According to the manpage, this is enough to read at least one event.
    static constexpr size_t kBufferSize = sizeof(struct inotify_event) + NAME_MAX + 1;
    char buffer[kBufferSize];

    do {
        ssize_t rv = TEMP_FAILURE_RETRY(read(inotify_fd_, buffer, sizeof(buffer)));
        if (rv <= 0) {
            if (rv == 0 || errno == EAGAIN) {
                return true;
            }
            PLOG(ERROR) << "read inotify failed";
            return false;
        }
    } while (true);
}

int64_t OneShotInotify::RemainingMs() const {
    auto remaining = (std::chrono::steady_clock::now() - start_time_);
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(remaining);
    return (relative_timeout_ - elapsed).count();
}
#endif

bool WaitForFile(const std::string& path, const std::chrono::milliseconds relative_timeout) {
#if defined(__linux__)
    OneShotInotify inotify(path, IN_CREATE, relative_timeout);
    return inotify.Wait();
#else
    return PollForFile(path, relative_timeout);
#endif
}

// Wait at most |relative_timeout| milliseconds for |path| to stop existing.
bool WaitForFileDeleted(const std::string& path, const std::chrono::milliseconds relative_timeout) {
#if defined(__linux__)
    OneShotInotify inotify(path, IN_DELETE_SELF, relative_timeout);
    return inotify.Wait();
#else
    return PollForFileDeleted(path, relative_timeout);
#endif
}

}  // namespace fs_mgr
}  // namespace android
