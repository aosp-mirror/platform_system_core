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

#include <android-base/logging.h>
#include <android-base/properties.h>
#include <libsnapshot/snapuserd_client.h>

namespace android {
namespace snapshot {

using namespace std::chrono_literals;
using android::base::unique_fd;

bool EnsureSnapuserdStarted() {
    if (android::base::GetProperty("init.svc.snapuserd", "") == "running") {
        return true;
    }

    android::base::SetProperty("ctl.start", "snapuserd");
    if (!android::base::WaitForProperty("init.svc.snapuserd", "running", 10s)) {
        LOG(ERROR) << "Timed out waiting for snapuserd to start.";
        return false;
    }
    return true;
}

SnapuserdClient::SnapuserdClient(android::base::unique_fd&& sockfd) : sockfd_(std::move(sockfd)) {}

static inline bool IsRetryErrno() {
    return errno == ECONNREFUSED || errno == EINTR;
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
    // is passive during transition phase. Please see RestartSnapuserd()
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
    ssize_t numBytesSent = TEMP_FAILURE_RETRY(send(sockfd_, msg.data(), msg.size(), 0));
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

bool SnapuserdClient::InitializeSnapuserd(const std::string& cow_device,
                                          const std::string& backing_device,
                                          const std::string& control_device) {
    std::string msg = "start," + cow_device + "," + backing_device + "," + control_device;
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

/*
 * Transition from first stage snapuserd daemon to second stage daemon involves
 * series of steps viz:
 *
 * 1: Create new dm-user devices - This is done by libsnapshot
 *
 * 2: Spawn the new snapuserd daemon - This is the second stage daemon which
 * will start the server but the dm-user misc devices is not binded yet.
 *
 * 3: Vector to this function contains pair of cow_device and source device.
 *    Ex: {{system_cow,system_a}, {product_cow, product_a}, {vendor_cow,
 *    vendor_a}}. This vector will be populated by the libsnapshot.
 *
 * 4: Initialize the Second stage daemon passing the information from the
 * vector. This will bind the daemon with dm-user misc device and will be ready
 * to serve the IO. Up until this point, first stage daemon is still active.
 * However, client library will mark the first stage daemon as passive and hence
 * all the control message from hereon will be sent to active second stage
 * daemon.
 *
 * 5: Create new dm-snapshot table. This is done by libsnapshot. When new table
 * is created, kernel will issue metadata read once again which will be served
 * by second stage daemon. However, any active IO will still be served by first
 * stage daemon.
 *
 * 6: Swap the snapshot table atomically - This is done by libsnapshot. Once
 * the swapping is done, all the IO will be served by second stage daemon.
 *
 * 7: Stop the first stage daemon. After this point second stage daemon is
 * completely active to serve the IO and merging process.
 *
 */
int SnapuserdClient::RestartSnapuserd(std::vector<std::vector<std::string>>& vec) {
    std::string msg = "terminate-request";
    if (!Sendmsg(msg)) {
        LOG(ERROR) << "Failed to send message " << msg << " to snapuserd daemon";
        return -1;
    }

    std::string str = Receivemsg();

    if (str.find("fail") != std::string::npos) {
        LOG(ERROR) << "Failed to receive ack for " << msg << " from snapuserd daemon";
        return -1;
    }

    CHECK(str.find("success") != std::string::npos);

    // Start the new daemon
    if (!EnsureSnapuserdStarted()) {
        LOG(ERROR) << "Failed to start new daemon";
        return -1;
    }

    LOG(DEBUG) << "Second stage Snapuserd daemon created successfully";

    // Vector contains all the device information to be passed to the new
    // daemon. Note that the caller can choose to initialize separately
    // by calling InitializeSnapuserd() API as well. In that case, vector
    // should be empty
    for (int i = 0; i < vec.size(); i++) {
        std::string& cow_device = vec[i][0];
        std::string& base_device = vec[i][1];
        std::string& control_device = vec[i][2];

        InitializeSnapuserd(cow_device, base_device, control_device);
        LOG(DEBUG) << "Daemon initialized with " << cow_device << ", " << base_device << " and "
                   << control_device;
    }

    return 0;
}

}  // namespace snapshot
}  // namespace android
