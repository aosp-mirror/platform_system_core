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

#include <stdint.h>

#include <arpa/inet.h>
#include <cutils/sockets.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <errno.h>
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
    TERMINATING,
    STOP,
    INVALID,
};

class Client {
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

    virtual void ThreadStart(std::string cow_device, std::string backing_device) = 0;

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
    std::vector<std::unique_ptr<Client>> clients_vec_;
    void ThreadStart(std::string cow_device, std::string backing_device) override;
    void ShutdownThreads();
    DaemonOperations Resolveop(std::string& input);
    std::string GetDaemonStatus();
    void Parsemsg(std::string const& msg, const char delim, std::vector<std::string>& out);

    void SetTerminating() { terminating_ = true; }

    bool IsTerminating() { return terminating_; }

  public:
    ~SnapuserdServer() { clients_vec_.clear(); }

    SnapuserdServer() { terminating_ = false; }

    int Start(std::string socketname);
    int AcceptClient();
    int Receivemsg(int fd);
    int Sendmsg(int fd, char* msg, size_t len);
    std::string Recvmsg(int fd, int* ret);
};

}  // namespace snapshot
}  // namespace android
