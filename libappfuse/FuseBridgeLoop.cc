/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "libappfuse/FuseBridgeLoop.h"

#include <sys/epoll.h>
#include <sys/socket.h>

#include <unordered_map>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

#include "libappfuse/EpollController.h"

namespace android {
namespace fuse {
namespace {

enum class FuseBridgeState { kWaitToReadEither, kWaitToReadProxy, kWaitToWriteProxy, kClosing };

struct FuseBridgeEntryEvent {
    FuseBridgeEntry* entry;
    int events;
};

void GetObservedEvents(FuseBridgeState state, int* device_events, int* proxy_events) {
    switch (state) {
        case FuseBridgeState::kWaitToReadEither:
            *device_events = EPOLLIN;
            *proxy_events = EPOLLIN;
            return;
        case FuseBridgeState::kWaitToReadProxy:
            *device_events = 0;
            *proxy_events = EPOLLIN;
            return;
        case FuseBridgeState::kWaitToWriteProxy:
            *device_events = 0;
            *proxy_events = EPOLLOUT;
            return;
        case FuseBridgeState::kClosing:
            *device_events = 0;
            *proxy_events = 0;
            return;
    }
}

void LogResponseError(const std::string& message, const FuseResponse& response) {
    LOG(ERROR) << message << ": header.len=" << response.header.len
               << " header.error=" << response.header.error
               << " header.unique=" << response.header.unique;
}
}

class FuseBridgeEntry {
  public:
    FuseBridgeEntry(int mount_id, base::unique_fd&& dev_fd, base::unique_fd&& proxy_fd)
        : mount_id_(mount_id),
          device_fd_(std::move(dev_fd)),
          proxy_fd_(std::move(proxy_fd)),
          state_(FuseBridgeState::kWaitToReadEither),
          last_state_(FuseBridgeState::kWaitToReadEither),
          last_device_events_({this, 0}),
          last_proxy_events_({this, 0}),
          open_count_(0) {}

    // Transfer bytes depends on availability of FDs and the internal |state_|.
    void Transfer(FuseBridgeLoopCallback* callback) {
        constexpr int kUnexpectedEventMask = ~(EPOLLIN | EPOLLOUT);
        const bool unexpected_event = (last_device_events_.events & kUnexpectedEventMask) ||
                                      (last_proxy_events_.events & kUnexpectedEventMask);
        const bool device_read_ready = last_device_events_.events & EPOLLIN;
        const bool proxy_read_ready = last_proxy_events_.events & EPOLLIN;
        const bool proxy_write_ready = last_proxy_events_.events & EPOLLOUT;

        last_state_ = state_;
        last_device_events_.events = 0;
        last_proxy_events_.events = 0;

        LOG(VERBOSE) << "Transfer device_read_ready=" << device_read_ready
                     << " proxy_read_ready=" << proxy_read_ready
                     << " proxy_write_ready=" << proxy_write_ready;

        if (unexpected_event) {
            LOG(ERROR) << "Invalid epoll event is observed";
            state_ = FuseBridgeState::kClosing;
            return;
        }

        switch (state_) {
            case FuseBridgeState::kWaitToReadEither:
                if (proxy_read_ready) {
                    state_ = ReadFromProxy();
                } else if (device_read_ready) {
                    state_ = ReadFromDevice(callback);
                }
                return;

            case FuseBridgeState::kWaitToReadProxy:
                CHECK(proxy_read_ready);
                state_ = ReadFromProxy();
                return;

            case FuseBridgeState::kWaitToWriteProxy:
                CHECK(proxy_write_ready);
                state_ = WriteToProxy();
                return;

            case FuseBridgeState::kClosing:
                return;
        }
    }

    bool IsClosing() const { return state_ == FuseBridgeState::kClosing; }

    int mount_id() const { return mount_id_; }

  private:
    friend class BridgeEpollController;

    FuseBridgeState ReadFromProxy() {
        switch (buffer_.response.ReadOrAgain(proxy_fd_)) {
            case ResultOrAgain::kSuccess:
                break;
            case ResultOrAgain::kFailure:
                return FuseBridgeState::kClosing;
            case ResultOrAgain::kAgain:
                return FuseBridgeState::kWaitToReadProxy;
        }

        if (!buffer_.response.Write(device_fd_)) {
            LogResponseError("Failed to write a reply from proxy to device", buffer_.response);
            return FuseBridgeState::kClosing;
        }

        auto it = opcode_map_.find(buffer_.response.header.unique);
        if (it != opcode_map_.end()) {
            switch (it->second) {
                case FUSE_OPEN:
                    if (buffer_.response.header.error == fuse::kFuseSuccess) {
                        open_count_++;
                    }
                    break;

                case FUSE_RELEASE:
                    if (open_count_ > 0) {
                        open_count_--;
                    } else {
                        LOG(WARNING) << "Unexpected FUSE_RELEASE before opening a file.";
                        break;
                    }
                    if (open_count_ == 0) {
                        return FuseBridgeState::kClosing;
                    }
                    break;
            }
            opcode_map_.erase(it);
        }

        return FuseBridgeState::kWaitToReadEither;
    }

    FuseBridgeState ReadFromDevice(FuseBridgeLoopCallback* callback) {
        LOG(VERBOSE) << "ReadFromDevice";
        if (!buffer_.request.Read(device_fd_)) {
            return FuseBridgeState::kClosing;
        }

        const uint32_t opcode = buffer_.request.header.opcode;
        const uint64_t unique = buffer_.request.header.unique;
        LOG(VERBOSE) << "Read a fuse packet, opcode=" << opcode << " unique=" << unique;
        if (unique == 0) {
            return FuseBridgeState::kWaitToReadEither;
        }
        switch (opcode) {
            case FUSE_FORGET:
                // Do not reply to FUSE_FORGET.
                return FuseBridgeState::kWaitToReadEither;

            case FUSE_LOOKUP:
            case FUSE_GETATTR:
            case FUSE_OPEN:
            case FUSE_READ:
            case FUSE_WRITE:
            case FUSE_RELEASE:
            case FUSE_FSYNC:
                if (opcode == FUSE_OPEN || opcode == FUSE_RELEASE) {
                    opcode_map_.emplace(buffer_.request.header.unique, opcode);
                }
                return WriteToProxy();

            case FUSE_INIT:
                buffer_.HandleInit();
                break;

            default:
                buffer_.HandleNotImpl();
                break;
        }

        if (!buffer_.response.Write(device_fd_)) {
            LogResponseError("Failed to write a response to device", buffer_.response);
            return FuseBridgeState::kClosing;
        }

        if (opcode == FUSE_INIT) {
            callback->OnMount(mount_id_);
        }

        return FuseBridgeState::kWaitToReadEither;
    }

    FuseBridgeState WriteToProxy() {
        switch (buffer_.request.WriteOrAgain(proxy_fd_)) {
            case ResultOrAgain::kSuccess:
                return FuseBridgeState::kWaitToReadEither;
            case ResultOrAgain::kFailure:
                LOG(ERROR) << "Failed to write a request to proxy:"
                           << " header.len=" << buffer_.request.header.len
                           << " header.opcode=" << buffer_.request.header.opcode
                           << " header.unique=" << buffer_.request.header.unique
                           << " header.nodeid=" << buffer_.request.header.nodeid;
                return FuseBridgeState::kClosing;
            case ResultOrAgain::kAgain:
                return FuseBridgeState::kWaitToWriteProxy;
        }
    }

    const int mount_id_;
    base::unique_fd device_fd_;
    base::unique_fd proxy_fd_;
    FuseBuffer buffer_;
    FuseBridgeState state_;
    FuseBridgeState last_state_;
    FuseBridgeEntryEvent last_device_events_;
    FuseBridgeEntryEvent last_proxy_events_;

    // Remember map between unique and opcode in fuse_in_header so that we can
    // refer the opcode later.
    std::unordered_map<uint64_t, uint32_t> opcode_map_;

    int open_count_;

    DISALLOW_COPY_AND_ASSIGN(FuseBridgeEntry);
};

class BridgeEpollController : private EpollController {
  public:
    BridgeEpollController(base::unique_fd&& poll_fd) : EpollController(std::move(poll_fd)) {}

    bool AddBridgePoll(FuseBridgeEntry* bridge) const {
        return InvokeControl(EPOLL_CTL_ADD, bridge);
    }

    bool UpdateOrDeleteBridgePoll(FuseBridgeEntry* bridge) const {
        return InvokeControl(
            bridge->state_ != FuseBridgeState::kClosing ? EPOLL_CTL_MOD : EPOLL_CTL_DEL, bridge);
    }

    bool Wait(size_t bridge_count, std::unordered_set<FuseBridgeEntry*>* entries_out) {
        CHECK(entries_out);
        const size_t event_count = std::max<size_t>(bridge_count * 2, 1);
        if (!EpollController::Wait(event_count)) {
            return false;
        }
        entries_out->clear();
        for (const auto& event : events()) {
            FuseBridgeEntryEvent* const entry_event =
                reinterpret_cast<FuseBridgeEntryEvent*>(event.data.ptr);
            entry_event->events = event.events;
            entries_out->insert(entry_event->entry);
        }
        return true;
    }

  private:
    bool InvokeControl(int op, FuseBridgeEntry* bridge) const {
        LOG(VERBOSE) << "InvokeControl op=" << op << " bridge=" << bridge->mount_id_
                     << " state=" << static_cast<int>(bridge->state_)
                     << " last_state=" << static_cast<int>(bridge->last_state_);

        int last_device_events;
        int last_proxy_events;
        int device_events;
        int proxy_events;
        GetObservedEvents(bridge->last_state_, &last_device_events, &last_proxy_events);
        GetObservedEvents(bridge->state_, &device_events, &proxy_events);
        bool result = true;
        if (op != EPOLL_CTL_MOD || last_device_events != device_events) {
            result &= EpollController::InvokeControl(op, bridge->device_fd_, device_events,
                                                     &bridge->last_device_events_);
        }
        if (op != EPOLL_CTL_MOD || last_proxy_events != proxy_events) {
            result &= EpollController::InvokeControl(op, bridge->proxy_fd_, proxy_events,
                                                     &bridge->last_proxy_events_);
        }
        return result;
    }
};

std::recursive_mutex FuseBridgeLoop::mutex_;

FuseBridgeLoop::FuseBridgeLoop() : opened_(true) {
    base::unique_fd epoll_fd(epoll_create1(EPOLL_CLOEXEC));
    if (epoll_fd.get() == -1) {
        PLOG(ERROR) << "Failed to open FD for epoll";
        opened_ = false;
        return;
    }
    epoll_controller_.reset(new BridgeEpollController(std::move(epoll_fd)));
}

FuseBridgeLoop::~FuseBridgeLoop() { CHECK(bridges_.empty()); }

bool FuseBridgeLoop::AddBridge(int mount_id, base::unique_fd dev_fd, base::unique_fd proxy_fd) {
    LOG(VERBOSE) << "Adding bridge " << mount_id;

    std::unique_ptr<FuseBridgeEntry> bridge(
        new FuseBridgeEntry(mount_id, std::move(dev_fd), std::move(proxy_fd)));
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!opened_) {
        LOG(ERROR) << "Tried to add a mount to a closed bridge";
        return false;
    }
    if (bridges_.count(mount_id)) {
        LOG(ERROR) << "Tried to add a mount point that has already been added";
        return false;
    }
    if (!epoll_controller_->AddBridgePoll(bridge.get())) {
        return false;
    }

    bridges_.emplace(mount_id, std::move(bridge));
    return true;
}

bool FuseBridgeLoop::ProcessEventLocked(const std::unordered_set<FuseBridgeEntry*>& entries,
                                        FuseBridgeLoopCallback* callback) {
    for (auto entry : entries) {
        entry->Transfer(callback);
        if (!epoll_controller_->UpdateOrDeleteBridgePoll(entry)) {
            return false;
        }
        if (entry->IsClosing()) {
            const int mount_id = entry->mount_id();
            bridges_.erase(mount_id);
            callback->OnClosed(mount_id);
            if (bridges_.size() == 0) {
                // All bridges are now closed.
                return false;
            }
        }
    }
    return true;
}

void FuseBridgeLoop::Start(FuseBridgeLoopCallback* callback) {
    LOG(DEBUG) << "Start fuse bridge loop";
    std::unordered_set<FuseBridgeEntry*> entries;
    while (true) {
        const bool wait_result = epoll_controller_->Wait(bridges_.size(), &entries);
        LOG(VERBOSE) << "Receive epoll events";
        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!(wait_result && ProcessEventLocked(entries, callback))) {
                for (auto it = bridges_.begin(); it != bridges_.end();) {
                    callback->OnClosed(it->second->mount_id());
                    it = bridges_.erase(it);
                }
                opened_ = false;
                return;
            }
        }
    }
}

void FuseBridgeLoop::Lock() {
    mutex_.lock();
}

void FuseBridgeLoop::Unlock() {
    mutex_.unlock();
}

}  // namespace fuse
}  // namespace android
