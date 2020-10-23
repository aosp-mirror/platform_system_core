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

#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace android {
namespace snapshot {

static constexpr uint32_t PACKET_SIZE = 512;
static constexpr uint32_t MAX_CONNECT_RETRY_COUNT = 10;

static constexpr char kSnapuserdSocketFirstStage[] = "snapuserd_first_stage";
static constexpr char kSnapuserdSocket[] = "snapuserd";

class SnapuserdClient {
  private:
    int sockfd_ = 0;

    int Sendmsg(const char* msg, size_t size);
    std::string Receivemsg();
    int StartSnapuserdaemon(std::string socketname);
    bool ConnectToServerSocket(std::string socketname);
    bool ConnectToServer();

    void DisconnectFromServer() { close(sockfd_); }

    std::string GetSocketNameFirstStage() {
        static std::string snapd_one("snapdone");
        return snapd_one;
    }

    std::string GetSocketNameSecondStage() {
        static std::string snapd_two("snapdtwo");
        return snapd_two;
    }

  public:
    int StartSnapuserd();
    int StopSnapuserd(bool firstStageDaemon);
    int RestartSnapuserd(std::vector<std::vector<std::string>>& vec);
    int InitializeSnapuserd(std::string cow_device, std::string backing_device,
                            std::string control_device);
};

}  // namespace snapshot
}  // namespace android
