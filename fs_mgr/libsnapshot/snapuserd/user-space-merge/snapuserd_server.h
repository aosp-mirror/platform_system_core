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
#include <sys/eventfd.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <android-base/unique_fd.h>
#include <snapuserd/block_server.h>
#include "handler_manager.h"
#include "snapuserd_core.h"

namespace android {
namespace snapshot {

static constexpr uint32_t kMaxPacketSize = 512;
static constexpr uint8_t kMaxMergeThreads = 2;
static constexpr char kBootSnapshotsWithoutSlotSwitch[] =
        "/metadata/ota/snapshot-boot-without-slot-switch";

class UserSnapshotServer {
  private:
    android::base::unique_fd sockfd_;
    bool terminating_;
    volatile bool received_socket_signal_ = false;
    std::vector<struct pollfd> watched_fds_;
    bool is_socket_present_ = false;
    bool is_server_running_ = false;
    bool io_uring_enabled_ = false;
    std::unique_ptr<ISnapshotHandlerManager> handlers_;
    std::unique_ptr<IBlockServerFactory> block_server_factory_;

    std::mutex lock_;

    void AddWatchedFd(android::base::borrowed_fd fd, int events);
    void AcceptClient();
    bool HandleClient(android::base::borrowed_fd fd, int revents);
    bool Recv(android::base::borrowed_fd fd, std::string* data);
    bool Sendmsg(android::base::borrowed_fd fd, const std::string& msg);
    bool Receivemsg(android::base::borrowed_fd fd, const std::string& str);

    void ShutdownThreads();
    std::string GetDaemonStatus();
    void Parsemsg(std::string const& msg, const char delim, std::vector<std::string>& out);

    bool IsTerminating() { return terminating_; }

    void JoinAllThreads();
    bool StartWithSocket(bool start_listening);

  public:
    UserSnapshotServer();
    ~UserSnapshotServer();

    bool Start(const std::string& socketname);
    bool Run();
    void Interrupt();
    bool RunForSocketHandoff();
    bool WaitForSocket();

    std::shared_ptr<HandlerThread> AddHandler(const std::string& misc_name,
                                              const std::string& cow_device_path,
                                              const std::string& backing_device,
                                              const std::string& base_path_merge);
    bool StartHandler(const std::string& misc_name);

    void SetTerminating() { terminating_ = true; }
    void ReceivedSocketSignal() { received_socket_signal_ = true; }
    void SetServerRunning() { is_server_running_ = true; }
    bool IsServerRunning() { return is_server_running_; }
    void SetIouringEnabled() { io_uring_enabled_ = true; }
    bool IsIouringEnabled() { return io_uring_enabled_; }
};

}  // namespace snapshot
}  // namespace android
