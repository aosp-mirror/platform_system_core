/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <arpa/inet.h>
#include <cutils/sockets.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <sstream>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <fs_mgr/file_wait.h>
#include <snapuserd/snapuserd_client.h>

namespace android {
namespace snapshot {

using namespace std::chrono_literals;
using android::base::unique_fd;

bool EnsureSnapuserdStarted() {
    if (android::base::GetProperty("init.svc.snapuserd", "") != "running") {
        android::base::SetProperty("ctl.start", "snapuserd");
        if (!android::base::WaitForProperty("init.svc.snapuserd", "running", 10s)) {
            LOG(ERROR) << "Timed out waiting for snapuserd to start.";
            return false;
        }
    }
    if (!android::base::WaitForProperty("snapuserd.ready", "true", 10s)) {
        LOG(ERROR) << "Timed out waiting for snapuserd to be ready.";
        return false;
    }
    return true;
}

SnapuserdClient::SnapuserdClient(android::base::unique_fd&& sockfd) : sockfd_(std::move(sockfd)) {}

static inline bool IsRetryErrno() {
    return errno == ECONNREFUSED || errno == EINTR || errno == ENOENT;
}

std::unique_ptr<SnapuserdClient> SnapuserdClient::Connect(const std::string& socket_name,
                                                          std::chrono::milliseconds timeout_ms) {
    unique_fd fd;
    auto start = std::chrono::steady_clock::now();
    while (true) {
        fd.reset(socket_local_client(socket_name.c_str(), ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_STREAM));
        if (fd >= 0) break;
        if (fd < 0 && !IsRetryErrno()) {
            PLOG(ERROR) << "connect failed: " << socket_name;
            return nullptr;
        }

        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start);
        if (elapsed >= timeout_ms) {
            LOG(ERROR) << "Timed out connecting to snapuserd socket: " << socket_name;
            return nullptr;
        }

        std::this_thread::sleep_for(100ms);
    }

    auto client = std::make_unique<SnapuserdClient>(std::move(fd));
    if (!client->ValidateConnection()) {
        return nullptr;
    }
    return client;
}

bool SnapuserdClient::ValidateConnection() {
    if (!Sendmsg("query")) {
        return false;
    }

    std::string str = Receivemsg();

    // If the daemon is passive then fallback to secondary active daemon. Daemon
    // is passive during transition phase.
    if (str.find("passive") != std::string::npos) {
        LOG(ERROR) << "Snapuserd is terminating";
        return false;
    }

    if (str != "active") {
        LOG(ERROR) << "Received failure querying daemon";
        return false;
    }
    return true;
}

bool SnapuserdClient::Sendmsg(const std::string& msg) {
    LOG(DEBUG) << "Sendmsg: msg " << msg << " sockfd: " << sockfd_;
    ssize_t numBytesSent = TEMP_FAILURE_RETRY(send(sockfd_, msg.data(), msg.size(), MSG_NOSIGNAL));
    if (numBytesSent < 0) {
        PLOG(ERROR) << "Send failed";
        return false;
    }

    if ((size_t)numBytesSent < msg.size()) {
        LOG(ERROR) << "Partial data sent, expected " << msg.size() << " bytes, sent "
                   << numBytesSent;
        return false;
    }
    return true;
}

bool SnapuserdClient::WaitForDeviceDelete(const std::string& control_device) {
    std::string msg = "delete," + control_device;
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd";
        return false;
    }
    std::string response = Receivemsg();
    if (response != "success") {
        LOG(ERROR) << "Failed waiting to delete device " << control_device;
        return false;
    }
    return true;
}

bool SnapuserdClient::SupportsSecondStageSocketHandoff() {
    std::string msg = "supports,second_stage_socket_handoff";
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd";
        return false;
    }
    std::string response = Receivemsg();
    return response == "success";
}

std::string SnapuserdClient::Receivemsg() {
    char msg[PACKET_SIZE];
    ssize_t ret = TEMP_FAILURE_RETRY(recv(sockfd_, msg, sizeof(msg), 0));
    if (ret < 0) {
        PLOG(ERROR) << "Snapuserd:client: recv failed";
        return {};
    }
    if (ret == 0) {
        LOG(DEBUG) << "Snapuserd:client disconnected";
        return {};
    }
    return std::string(msg, ret);
}

bool SnapuserdClient::StopSnapuserd() {
    if (!Sendmsg("stop")) {
        LOG(ERROR) << "Failed to send stop message to snapuserd daemon";
        return false;
    }

    sockfd_ = {};
    return true;
}

bool SnapuserdClient::AttachDmUser(const std::string& misc_name) {
    std::string msg = "start," + misc_name;
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd daemon";
        return false;
    }

    std::string str = Receivemsg();
    if (str != "success") {
        LOG(ERROR) << "Failed to receive ack for " << msg << " from snapuserd daemon";
        return false;
    }

    LOG(DEBUG) << "Snapuserd daemon initialized with " << msg;
    return true;
}

uint64_t SnapuserdClient::InitDmUserCow(const std::string& misc_name, const std::string& cow_device,
                                        const std::string& backing_device,
                                        const std::string& base_path_merge) {
    std::vector<std::string> parts;

    if (base_path_merge.empty()) {
        parts = {"init", misc_name, cow_device, backing_device};
    } else {
        // For userspace snapshots
        parts = {"init", misc_name, cow_device, backing_device, base_path_merge};
    }
    std::string msg = android::base::Join(parts, ",");
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd daemon";
        return 0;
    }

    std::string str = Receivemsg();

    std::vector<std::string> input = android::base::Split(str, ",");

    if (input.empty() || input[0] != "success") {
        LOG(ERROR) << "Failed to receive number of sectors for " << msg << " from snapuserd daemon";
        return 0;
    }

    LOG(DEBUG) << "Snapuserd daemon COW device initialized: " << cow_device
               << " Num-sectors: " << input[1];

    uint64_t num_sectors = 0;
    if (!android::base::ParseUint(input[1], &num_sectors)) {
        LOG(ERROR) << "Failed to parse input string to sectors";
        return 0;
    }
    return num_sectors;
}

bool SnapuserdClient::DetachSnapuserd() {
    if (!Sendmsg("detach")) {
        LOG(ERROR) << "Failed to detach snapuserd.";
        return false;
    }
    return true;
}

bool SnapuserdClient::InitiateMerge(const std::string& misc_name) {
    std::string msg = "initiate_merge," + misc_name;
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd";
        return false;
    }
    std::string response = Receivemsg();
    return response == "success";
}

double SnapuserdClient::GetMergePercent() {
    std::string msg = "merge_percent";
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd";
        return false;
    }
    std::string response = Receivemsg();

    return std::stod(response);
}

std::string SnapuserdClient::QuerySnapshotStatus(const std::string& misc_name) {
    std::string msg = "getstatus," + misc_name;
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd";
        return "snapshot-merge-failed";
    }
    return Receivemsg();
}

bool SnapuserdClient::QueryUpdateVerification() {
    std::string msg = "update-verify";
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd";
        return false;
    }
    std::string response = Receivemsg();
    return response == "success";
}

std::string SnapuserdClient::GetDaemonAliveIndicatorPath() {
    return "/metadata/ota/" + std::string(kDaemonAliveIndicator);
}

bool SnapuserdClient::IsTransitionedDaemonReady() {
    if (!android::fs_mgr::WaitForFile(GetDaemonAliveIndicatorPath(), 10s)) {
        LOG(ERROR) << "Timed out waiting for daemon indicator path: "
                   << GetDaemonAliveIndicatorPath();
        return false;
    }

    return true;
}

bool SnapuserdClient::RemoveTransitionedDaemonIndicator() {
    std::string error;
    std::string filePath = GetDaemonAliveIndicatorPath();
    if (!android::base::RemoveFileIfExists(filePath, &error)) {
        LOG(ERROR) << "Failed to remove DaemonAliveIndicatorPath - error: " << error;
        return false;
    }

    if (!android::fs_mgr::WaitForFileDeleted(filePath, 5s)) {
        LOG(ERROR) << "Timed out waiting for " << filePath << " to unlink";
        return false;
    }

    return true;
}

void SnapuserdClient::NotifyTransitionDaemonIsReady() {
    if (!android::base::WriteStringToFile("1", GetDaemonAliveIndicatorPath())) {
        PLOG(ERROR) << "Unable to write daemon alive indicator path: "
                    << GetDaemonAliveIndicatorPath();
    }
}

}  // namespace snapshot
}  // namespace android
