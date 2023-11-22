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
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <android-base/cmsg.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/strings.h>
#include <fs_mgr/file_wait.h>
#include <snapuserd/dm_user_block_server.h>
#include <snapuserd/snapuserd_client.h>
#include "snapuserd_server.h"

#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>

namespace android {
namespace snapshot {

using namespace std::string_literals;

using android::base::borrowed_fd;
using android::base::unique_fd;

UserSnapshotServer::UserSnapshotServer() {
    terminating_ = false;
    handlers_ = std::make_unique<SnapshotHandlerManager>();
    block_server_factory_ = std::make_unique<DmUserBlockServerFactory>();
}

UserSnapshotServer::~UserSnapshotServer() {
    // Close any client sockets that were added via AcceptClient().
    for (size_t i = 1; i < watched_fds_.size(); i++) {
        close(watched_fds_[i].fd);
    }
}

std::string UserSnapshotServer::GetDaemonStatus() {
    std::string msg = "";

    if (IsTerminating())
        msg = "passive";
    else
        msg = "active";

    return msg;
}

void UserSnapshotServer::Parsemsg(std::string const& msg, const char delim,
                                  std::vector<std::string>& out) {
    std::stringstream ss(msg);
    std::string s;

    while (std::getline(ss, s, delim)) {
        out.push_back(s);
    }
}

void UserSnapshotServer::ShutdownThreads() {
    terminating_ = true;
    handlers_->JoinAllThreads();
}

bool UserSnapshotServer::Sendmsg(android::base::borrowed_fd fd, const std::string& msg) {
    ssize_t ret = TEMP_FAILURE_RETRY(send(fd.get(), msg.data(), msg.size(), MSG_NOSIGNAL));
    if (ret < 0) {
        PLOG(ERROR) << "Snapuserd:server: send() failed";
        return false;
    }

    if (ret < msg.size()) {
        LOG(ERROR) << "Partial send; expected " << msg.size() << " bytes, sent " << ret;
        return false;
    }
    return true;
}

bool UserSnapshotServer::Recv(android::base::borrowed_fd fd, std::string* data) {
    char msg[kMaxPacketSize];
    ssize_t rv = TEMP_FAILURE_RETRY(recv(fd.get(), msg, sizeof(msg), 0));
    if (rv < 0) {
        PLOG(ERROR) << "recv failed";
        return false;
    }
    *data = std::string(msg, rv);
    return true;
}

bool UserSnapshotServer::Receivemsg(android::base::borrowed_fd fd, const std::string& str) {
    const char delim = ',';

    std::vector<std::string> out;
    Parsemsg(str, delim, out);

    const auto& cmd = out[0];
    if (cmd == "init") {
        // Message format:
        // init,<misc_name>,<cow_device_path>,<backing_device>,<base_path_merge>
        //
        // Reads the metadata and send the number of sectors
        if (out.size() != 5) {
            LOG(ERROR) << "Malformed init message, " << out.size() << " parts";
            return Sendmsg(fd, "fail");
        }

        auto handler = AddHandler(out[1], out[2], out[3], out[4]);
        if (!handler) {
            return Sendmsg(fd, "fail");
        }

        auto num_sectors = handler->snapuserd()->GetNumSectors();
        if (!num_sectors) {
            return Sendmsg(fd, "fail");
        }

        auto retval = "success," + std::to_string(num_sectors);
        return Sendmsg(fd, retval);
    } else if (cmd == "start") {
        // Message format:
        // start,<misc_name>
        //
        // Start the new thread which binds to dm-user misc device
        if (out.size() != 2) {
            LOG(ERROR) << "Malformed start message, " << out.size() << " parts";
            return Sendmsg(fd, "fail");
        }

        if (!handlers_->StartHandler(out[1])) {
            return Sendmsg(fd, "fail");
        }
        return Sendmsg(fd, "success");
    } else if (cmd == "stop") {
        // Message format: stop
        //
        // Stop all the threads gracefully and then shutdown the
        // main thread
        SetTerminating();
        ShutdownThreads();
        return true;
    } else if (cmd == "query") {
        // Message format: query
        //
        // As part of transition, Second stage daemon will be
        // created before terminating the first stage daemon. Hence,
        // for a brief period client may have to distiguish between
        // first stage daemon and second stage daemon.
        //
        // Second stage daemon is marked as active and hence will
        // be ready to receive control message.
        return Sendmsg(fd, GetDaemonStatus());
    } else if (cmd == "delete") {
        // Message format:
        // delete,<misc_name>
        if (out.size() != 2) {
            LOG(ERROR) << "Malformed delete message, " << out.size() << " parts";
            return Sendmsg(fd, "fail");
        }
        if (!handlers_->DeleteHandler(out[1])) {
            return Sendmsg(fd, "fail");
        }
        return Sendmsg(fd, "success");
    } else if (cmd == "detach") {
        handlers_->TerminateMergeThreads();
        terminating_ = true;
        return true;
    } else if (cmd == "supports") {
        if (out.size() != 2) {
            LOG(ERROR) << "Malformed supports message, " << out.size() << " parts";
            return Sendmsg(fd, "fail");
        }
        if (out[1] == "second_stage_socket_handoff") {
            return Sendmsg(fd, "success");
        }
        return Sendmsg(fd, "fail");
    } else if (cmd == "initiate_merge") {
        if (out.size() != 2) {
            LOG(ERROR) << "Malformed initiate-merge message, " << out.size() << " parts";
            return Sendmsg(fd, "fail");
        }
        if (out[0] == "initiate_merge") {
            if (!handlers_->InitiateMerge(out[1])) {
                return Sendmsg(fd, "fail");
            }
            return Sendmsg(fd, "success");
        }
        return Sendmsg(fd, "fail");
    } else if (cmd == "merge_percent") {
        double percentage = handlers_->GetMergePercentage();
        return Sendmsg(fd, std::to_string(percentage));
    } else if (cmd == "getstatus") {
        // Message format:
        // getstatus,<misc_name>
        if (out.size() != 2) {
            LOG(ERROR) << "Malformed delete message, " << out.size() << " parts";
            return Sendmsg(fd, "snapshot-merge-failed");
        }
        auto status = handlers_->GetMergeStatus(out[1]);
        if (status.empty()) {
            return Sendmsg(fd, "snapshot-merge-failed");
        }
        return Sendmsg(fd, status);
    } else if (cmd == "update-verify") {
        if (!handlers_->GetVerificationStatus()) {
            return Sendmsg(fd, "fail");
        }
        return Sendmsg(fd, "success");
    } else {
        LOG(ERROR) << "Received unknown message type from client";
        Sendmsg(fd, "fail");
        return false;
    }
}

bool UserSnapshotServer::Start(const std::string& socketname) {
    bool start_listening = true;

    sockfd_.reset(android_get_control_socket(socketname.c_str()));
    if (sockfd_ < 0) {
        sockfd_.reset(socket_local_server(socketname.c_str(), ANDROID_SOCKET_NAMESPACE_RESERVED,
                                          SOCK_STREAM));
        if (sockfd_ < 0) {
            PLOG(ERROR) << "Failed to create server socket " << socketname;
            return false;
        }
        start_listening = false;
    }
    return StartWithSocket(start_listening);
}

bool UserSnapshotServer::StartWithSocket(bool start_listening) {
    if (start_listening && listen(sockfd_.get(), 4) < 0) {
        PLOG(ERROR) << "listen socket failed";
        return false;
    }

    AddWatchedFd(sockfd_, POLLIN);
    is_socket_present_ = true;

    // If started in first-stage init, the property service won't be online.
    if (access("/dev/socket/property_service", F_OK) == 0) {
        if (!android::base::SetProperty("snapuserd.ready", "true")) {
            LOG(ERROR) << "Failed to set snapuserd.ready property";
            return false;
        }
    }

    LOG(DEBUG) << "Snapuserd server now accepting connections";
    return true;
}

bool UserSnapshotServer::Run() {
    LOG(INFO) << "Now listening on snapuserd socket";

    while (!IsTerminating()) {
        int rv = TEMP_FAILURE_RETRY(poll(watched_fds_.data(), watched_fds_.size(), -1));
        if (rv < 0) {
            PLOG(ERROR) << "poll failed";
            return false;
        }
        if (!rv) {
            continue;
        }

        if (watched_fds_[0].revents) {
            AcceptClient();
        }

        auto iter = watched_fds_.begin() + 1;
        while (iter != watched_fds_.end()) {
            if (iter->revents && !HandleClient(iter->fd, iter->revents)) {
                close(iter->fd);
                iter = watched_fds_.erase(iter);
            } else {
                iter++;
            }
        }
    }

    handlers_->JoinAllThreads();
    return true;
}

void UserSnapshotServer::AddWatchedFd(android::base::borrowed_fd fd, int events) {
    struct pollfd p = {};
    p.fd = fd.get();
    p.events = events;
    watched_fds_.emplace_back(std::move(p));
}

void UserSnapshotServer::AcceptClient() {
    int fd = TEMP_FAILURE_RETRY(accept4(sockfd_.get(), nullptr, nullptr, SOCK_CLOEXEC));
    if (fd < 0) {
        PLOG(ERROR) << "accept4 failed";
        return;
    }

    AddWatchedFd(fd, POLLIN);
}

bool UserSnapshotServer::HandleClient(android::base::borrowed_fd fd, int revents) {
    std::string str;
    if (!Recv(fd, &str)) {
        return false;
    }
    if (str.empty() && (revents & POLLHUP)) {
        LOG(DEBUG) << "Snapuserd client disconnected";
        return false;
    }
    if (!Receivemsg(fd, str)) {
        LOG(ERROR) << "Encountered error handling client message, revents: " << revents;
        return false;
    }
    return true;
}

void UserSnapshotServer::Interrupt() {
    // Force close the socket so poll() fails.
    sockfd_ = {};
    SetTerminating();
}

std::shared_ptr<HandlerThread> UserSnapshotServer::AddHandler(const std::string& misc_name,
                                                              const std::string& cow_device_path,
                                                              const std::string& backing_device,
                                                              const std::string& base_path_merge) {
    // We will need multiple worker threads only during
    // device boot after OTA. For all other purposes,
    // one thread is sufficient. We don't want to consume
    // unnecessary memory especially during OTA install phase
    // when daemon will be up during entire post install phase.
    //
    // During boot up, we need multiple threads primarily for
    // update-verification.
    int num_worker_threads = kNumWorkerThreads;
    if (is_socket_present_) {
        num_worker_threads = 1;
    }

    if (android::base::EndsWith(misc_name, "-init") || is_socket_present_ ||
        (access(kBootSnapshotsWithoutSlotSwitch, F_OK) == 0)) {
        handlers_->DisableVerification();
    }

    auto opener = block_server_factory_->CreateOpener(misc_name);

    return handlers_->AddHandler(misc_name, cow_device_path, backing_device, base_path_merge,
                                 opener, num_worker_threads, io_uring_enabled_);
}

bool UserSnapshotServer::WaitForSocket() {
    auto scope_guard =
            android::base::make_scope_guard([this]() -> void { handlers_->JoinAllThreads(); });

    auto socket_path = ANDROID_SOCKET_DIR "/"s + kSnapuserdSocketProxy;

    if (!android::fs_mgr::WaitForFile(socket_path, std::chrono::milliseconds::max())) {
        LOG(ERROR)
                << "Failed to wait for proxy socket, second-stage snapuserd will fail to connect";
        return false;
    }

    // This initialization of system property is important. When daemon is
    // launched post selinux transition (before init second stage),
    // bionic libc initializes system property as part of __libc_init_common();
    // however that initialization fails silently given that fact that we don't
    // have /dev/__properties__ setup which is created at init second stage.
    //
    // At this point, we have the handlers setup and is safe to setup property.
    __system_properties_init();

    if (!android::base::WaitForProperty("snapuserd.proxy_ready", "true")) {
        LOG(ERROR)
                << "Failed to wait for proxy property, second-stage snapuserd will fail to connect";
        return false;
    }

    unique_fd fd(socket_local_client(kSnapuserdSocketProxy, ANDROID_SOCKET_NAMESPACE_RESERVED,
                                     SOCK_SEQPACKET));
    if (fd < 0) {
        PLOG(ERROR) << "Failed to connect to socket proxy";
        return false;
    }

    char code[1];
    std::vector<unique_fd> fds;
    ssize_t rv = android::base::ReceiveFileDescriptorVector(fd, code, sizeof(code), 1, &fds);
    if (rv < 0) {
        PLOG(ERROR) << "Failed to receive server socket over proxy";
        return false;
    }
    if (fds.empty()) {
        LOG(ERROR) << "Expected at least one file descriptor from proxy";
        return false;
    }

    // We don't care if the ACK is received.
    code[0] = 'a';
    if (TEMP_FAILURE_RETRY(send(fd, code, sizeof(code), MSG_NOSIGNAL)) < 0) {
        PLOG(ERROR) << "Failed to send ACK to proxy";
        return false;
    }

    sockfd_ = std::move(fds[0]);
    if (!StartWithSocket(true)) {
        return false;
    }

    return Run();
}

bool UserSnapshotServer::RunForSocketHandoff() {
    unique_fd proxy_fd(android_get_control_socket(kSnapuserdSocketProxy));
    if (proxy_fd < 0) {
        PLOG(FATAL) << "Proxy could not get android control socket " << kSnapuserdSocketProxy;
    }
    borrowed_fd server_fd(android_get_control_socket(kSnapuserdSocket));
    if (server_fd < 0) {
        PLOG(FATAL) << "Proxy could not get android control socket " << kSnapuserdSocket;
    }

    if (listen(proxy_fd.get(), 4) < 0) {
        PLOG(FATAL) << "Proxy listen socket failed";
    }

    if (!android::base::SetProperty("snapuserd.proxy_ready", "true")) {
        LOG(FATAL) << "Proxy failed to set ready property";
    }

    unique_fd client_fd(
            TEMP_FAILURE_RETRY(accept4(proxy_fd.get(), nullptr, nullptr, SOCK_CLOEXEC)));
    if (client_fd < 0) {
        PLOG(FATAL) << "Proxy accept failed";
    }

    char code[1] = {'a'};
    std::vector<int> fds = {server_fd.get()};
    ssize_t rv = android::base::SendFileDescriptorVector(client_fd, code, sizeof(code), fds);
    if (rv < 0) {
        PLOG(FATAL) << "Proxy could not send file descriptor to snapuserd";
    }
    // Wait for an ACK - results don't matter, we just don't want to risk closing
    // the proxy socket too early.
    if (recv(client_fd, code, sizeof(code), 0) < 0) {
        PLOG(FATAL) << "Proxy could not receive terminating code from snapuserd";
    }
    return true;
}

bool UserSnapshotServer::StartHandler(const std::string& misc_name) {
    return handlers_->StartHandler(misc_name);
}

}  // namespace snapshot
}  // namespace android
