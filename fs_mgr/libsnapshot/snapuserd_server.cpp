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

#include <android-base/logging.h>
#include <libsnapshot/snapuserd.h>
#include <libsnapshot/snapuserd_server.h>

namespace android {
namespace snapshot {

DaemonOperations SnapuserdServer::Resolveop(std::string& input) {
    if (input == "start") return DaemonOperations::START;
    if (input == "stop") return DaemonOperations::STOP;
    if (input == "query") return DaemonOperations::QUERY;
    if (input == "delete") return DaemonOperations::DELETE;

    return DaemonOperations::INVALID;
}

SnapuserdServer::~SnapuserdServer() {
    // Close any client sockets that were added via AcceptClient().
    for (size_t i = 1; i < watched_fds_.size(); i++) {
        close(watched_fds_[i].fd);
    }
}

std::string SnapuserdServer::GetDaemonStatus() {
    std::string msg = "";

    if (IsTerminating())
        msg = "passive";
    else
        msg = "active";

    return msg;
}

void SnapuserdServer::Parsemsg(std::string const& msg, const char delim,
                               std::vector<std::string>& out) {
    std::stringstream ss(msg);
    std::string s;

    while (std::getline(ss, s, delim)) {
        out.push_back(s);
    }
}

void SnapuserdServer::ShutdownThreads() {
    StopThreads();

    // Acquire the thread list within the lock.
    std::vector<std::unique_ptr<DmUserHandler>> dm_users;
    {
        std::lock_guard<std::mutex> guard(lock_);
        dm_users = std::move(dm_users_);
    }

    for (auto& client : dm_users) {
        auto& th = client->thread();

        if (th.joinable()) th.join();
    }
}

const std::string& DmUserHandler::GetControlDevice() const {
    return snapuserd_->GetControlDevicePath();
}

bool SnapuserdServer::Sendmsg(android::base::borrowed_fd fd, const std::string& msg) {
    ssize_t ret = TEMP_FAILURE_RETRY(send(fd.get(), msg.data(), msg.size(), 0));
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

bool SnapuserdServer::Recv(android::base::borrowed_fd fd, std::string* data) {
    char msg[MAX_PACKET_SIZE];
    ssize_t rv = TEMP_FAILURE_RETRY(recv(fd.get(), msg, sizeof(msg), 0));
    if (rv < 0) {
        PLOG(ERROR) << "recv failed";
        return false;
    }
    *data = std::string(msg, rv);
    return true;
}

bool SnapuserdServer::Receivemsg(android::base::borrowed_fd fd, const std::string& str) {
    const char delim = ',';

    std::vector<std::string> out;
    Parsemsg(str, delim, out);
    DaemonOperations op = Resolveop(out[0]);

    switch (op) {
        case DaemonOperations::START: {
            // Message format:
            // start,<cow_device_path>,<source_device_path>,<control_device>
            //
            // Start the new thread which binds to dm-user misc device
            if (out.size() != 4) {
                LOG(ERROR) << "Malformed start message, " << out.size() << " parts";
                return Sendmsg(fd, "fail");
            }

            auto snapuserd = std::make_unique<Snapuserd>(out[1], out[2], out[3]);
            if (!snapuserd->Init()) {
                LOG(ERROR) << "Failed to initialize Snapuserd";
                return Sendmsg(fd, "fail");
            }

            auto handler = std::make_unique<DmUserHandler>(std::move(snapuserd));
            {
                std::lock_guard<std::mutex> lock(lock_);

                handler->thread() =
                        std::thread(std::bind(&SnapuserdServer::RunThread, this, handler.get()));
                dm_users_.push_back(std::move(handler));
            }
            return Sendmsg(fd, "success");
        }
        case DaemonOperations::STOP: {
            // Message format: stop
            //
            // Stop all the threads gracefully and then shutdown the
            // main thread
            SetTerminating();
            ShutdownThreads();
            return true;
        }
        case DaemonOperations::QUERY: {
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
        }
        case DaemonOperations::DELETE: {
            // Message format:
            // delete,<cow_device_path>
            if (out.size() != 2) {
                LOG(ERROR) << "Malformed delete message, " << out.size() << " parts";
                return Sendmsg(fd, "fail");
            }
            if (!WaitForDelete(out[1])) {
                return Sendmsg(fd, "fail");
            }
            return Sendmsg(fd, "success");
        }
        default: {
            LOG(ERROR) << "Received unknown message type from client";
            Sendmsg(fd, "fail");
            return false;
        }
    }
}

void SnapuserdServer::RunThread(DmUserHandler* handler) {
    while (!StopRequested()) {
        if (handler->snapuserd()->Run() < 0) {
            LOG(INFO) << "Snapuserd: Thread terminating as control device is de-registered";
            break;
        }
    }

    if (auto client = RemoveHandler(handler->GetControlDevice())) {
        // The main thread did not receive a WaitForDelete request for this
        // control device. Since we transferred ownership within the lock,
        // we know join() was never called, and will never be called. We can
        // safely detach here.
        client->thread().detach();
    }
}

bool SnapuserdServer::Start(const std::string& socketname) {
    sockfd_.reset(android_get_control_socket(socketname.c_str()));
    if (sockfd_ >= 0) {
        if (listen(sockfd_.get(), 4) < 0) {
            PLOG(ERROR) << "listen socket failed: " << socketname;
            return false;
        }
    } else {
        sockfd_.reset(socket_local_server(socketname.c_str(), ANDROID_SOCKET_NAMESPACE_RESERVED,
                                          SOCK_STREAM));
        if (sockfd_ < 0) {
            PLOG(ERROR) << "Failed to create server socket " << socketname;
            return false;
        }
    }

    AddWatchedFd(sockfd_);

    LOG(DEBUG) << "Snapuserd server successfully started with socket name " << socketname;
    return true;
}

bool SnapuserdServer::Run() {
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
    return true;
}

void SnapuserdServer::AddWatchedFd(android::base::borrowed_fd fd) {
    struct pollfd p = {};
    p.fd = fd.get();
    p.events = POLLIN;
    watched_fds_.emplace_back(std::move(p));
}

void SnapuserdServer::AcceptClient() {
    int fd = TEMP_FAILURE_RETRY(accept4(sockfd_.get(), nullptr, nullptr, SOCK_CLOEXEC));
    if (fd < 0) {
        PLOG(ERROR) << "accept4 failed";
        return;
    }

    AddWatchedFd(fd);
}

bool SnapuserdServer::HandleClient(android::base::borrowed_fd fd, int revents) {
    if (revents & POLLHUP) {
        LOG(DEBUG) << "Snapuserd client disconnected";
        return false;
    }

    std::string str;
    if (!Recv(fd, &str)) {
        return false;
    }
    if (!Receivemsg(fd, str)) {
        LOG(ERROR) << "Encountered error handling client message, revents: " << revents;
        return false;
    }
    return true;
}

void SnapuserdServer::Interrupt() {
    // Force close the socket so poll() fails.
    sockfd_ = {};
    SetTerminating();
}

std::unique_ptr<DmUserHandler> SnapuserdServer::RemoveHandler(const std::string& control_device) {
    std::unique_ptr<DmUserHandler> client;
    {
        std::lock_guard<std::mutex> lock(lock_);
        auto iter = dm_users_.begin();
        while (iter != dm_users_.end()) {
            if ((*iter)->GetControlDevice() == control_device) {
                client = std::move(*iter);
                iter = dm_users_.erase(iter);
                break;
            }
            iter++;
        }
    }
    return client;
}

bool SnapuserdServer::WaitForDelete(const std::string& control_device) {
    auto client = RemoveHandler(control_device);

    // Client already deleted.
    if (!client) {
        return true;
    }

    auto& th = client->thread();
    if (th.joinable()) {
        th.join();
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
