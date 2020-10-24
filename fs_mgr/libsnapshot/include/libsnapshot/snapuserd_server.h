// Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <poll.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <android-base/unique_fd.h>

namespace android {
namespace snapshot {

static constexpr uint32_t MAX_PACKET_SIZE = 512;

enum class DaemonOperations {
    START,
    QUERY,
    STOP,
    INVALID,
};

class DmUserHandler {
  private:
    std::unique_ptr<std::thread> threadHandler_;

  public:
    void SetThreadHandler(std::function<void(void)> func) {
        threadHandler_ = std::make_unique<std::thread>(func);
    }

    std::unique_ptr<std::thread>& GetThreadHandler() { return threadHandler_; }
};

class Stoppable {
    std::promise<void> exitSignal_;
    std::future<void> futureObj_;

  public:
    Stoppable() : futureObj_(exitSignal_.get_future()) {}

    virtual ~Stoppable() {}

    virtual void ThreadStart(std::string cow_device, std::string backing_device,
                             std::string control_device) = 0;

    bool StopRequested() {
        // checks if value in future object is available
        if (futureObj_.wait_for(std::chrono::milliseconds(0)) == std::future_status::timeout)
            return false;
        return true;
    }
    // Request the thread to stop by setting value in promise object
    void StopThreads() { exitSignal_.set_value(); }
};

class SnapuserdServer : public Stoppable {
  private:
    android::base::unique_fd sockfd_;
    bool terminating_;
    std::vector<std::unique_ptr<DmUserHandler>> dm_users_;
    std::vector<struct pollfd> watched_fds_;

    void AddWatchedFd(android::base::borrowed_fd fd);
    void AcceptClient();
    bool HandleClient(android::base::borrowed_fd fd, int revents);
    bool Recv(android::base::borrowed_fd fd, std::string* data);
    bool Sendmsg(android::base::borrowed_fd fd, const std::string& msg);
    bool Receivemsg(android::base::borrowed_fd fd, const std::string& msg);

    void ThreadStart(std::string cow_device, std::string backing_device,
                     std::string control_device) override;
    void ShutdownThreads();
    DaemonOperations Resolveop(std::string& input);
    std::string GetDaemonStatus();
    void Parsemsg(std::string const& msg, const char delim, std::vector<std::string>& out);

    void SetTerminating() { terminating_ = true; }

    bool IsTerminating() { return terminating_; }

  public:
    SnapuserdServer() { terminating_ = false; }
    ~SnapuserdServer();

    bool Start(const std::string& socketname);
    bool Run();
    void Interrupt();
};

}  // namespace snapshot
}  // namespace android
