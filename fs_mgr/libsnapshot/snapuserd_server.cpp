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

#include "snapuserd.h"
#include "snapuserd_server.h"

namespace android {
namespace snapshot {

DaemonOperations SnapuserdServer::Resolveop(std::string& input) {
    if (input == "init") return DaemonOperations::INIT;
    if (input == "start") return DaemonOperations::START;
    if (input == "stop") return DaemonOperations::STOP;
    if (input == "query") return DaemonOperations::QUERY;
    if (input == "delete") return DaemonOperations::DELETE;
    if (input == "detach") return DaemonOperations::DETACH;

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
    JoinAllThreads();
}

DmUserHandler::DmUserHandler(std::shared_ptr<Snapuserd> snapuserd)
    : snapuserd_(snapuserd), misc_name_(snapuserd_->GetMiscName()) {}

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
        case DaemonOperations::INIT: {
            // Message format:
            // init,<misc_name>,<cow_device_path>,<backing_device>
            //
            // Reads the metadata and send the number of sectors
            if (out.size() != 4) {
                LOG(ERROR) << "Malformed init message, " << out.size() << " parts";
                return Sendmsg(fd, "fail");
            }

            auto handler = AddHandler(out[1], out[2], out[3]);
            if (!handler) {
                return Sendmsg(fd, "fail");
            }

            auto retval = "success," + std::to_string(handler->snapuserd()->GetNumSectors());
            return Sendmsg(fd, retval);
        }
        case DaemonOperations::START: {
            // Message format:
            // start,<misc_name>
            //
            // Start the new thread which binds to dm-user misc device
            if (out.size() != 2) {
                LOG(ERROR) << "Malformed start message, " << out.size() << " parts";
                return Sendmsg(fd, "fail");
            }

            std::lock_guard<std::mutex> lock(lock_);
            auto iter = FindHandler(&lock, out[1]);
            if (iter == dm_users_.end()) {
                LOG(ERROR) << "Could not find handler: " << out[1];
                return Sendmsg(fd, "fail");
            }
            if (!(*iter)->snapuserd() || (*iter)->snapuserd()->IsAttached()) {
                LOG(ERROR) << "Tried to re-attach control device: " << out[1];
                return Sendmsg(fd, "fail");
            }
            if (!StartHandler(*iter)) {
                return Sendmsg(fd, "fail");
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
            // delete,<misc_name>
            if (out.size() != 2) {
                LOG(ERROR) << "Malformed delete message, " << out.size() << " parts";
                return Sendmsg(fd, "fail");
            }
            if (!RemoveAndJoinHandler(out[1])) {
                return Sendmsg(fd, "fail");
            }
            return Sendmsg(fd, "success");
        }
        case DaemonOperations::DETACH: {
            terminating_ = true;
            return Sendmsg(fd, "success");
        }
        default: {
            LOG(ERROR) << "Received unknown message type from client";
            Sendmsg(fd, "fail");
            return false;
        }
    }
}

void SnapuserdServer::RunThread(std::shared_ptr<DmUserHandler> handler) {
    LOG(INFO) << "Entering thread for handler: " << handler->misc_name();

    if (!handler->snapuserd()->Start()) {
        LOG(ERROR) << " Failed to launch all worker threads";
    }

    handler->snapuserd()->CloseFds();
    handler->snapuserd()->CheckMergeCompletionStatus();
    handler->snapuserd()->UnmapBufferRegion();

    auto misc_name = handler->misc_name();
    LOG(INFO) << "Handler thread about to exit: " << misc_name;

    {
        std::lock_guard<std::mutex> lock(lock_);
        auto iter = FindHandler(&lock, handler->misc_name());
        if (iter == dm_users_.end()) {
            // RemoveAndJoinHandler() already removed us from the list, and is
            // now waiting on a join(), so just return. Additionally, release
            // all the resources held by snapuserd object which are shared
            // by worker threads. This should be done when the last reference
            // of "handler" is released; but we will explicitly release here
            // to make sure snapuserd object is freed as it is the biggest
            // consumer of memory in the daemon.
            handler->FreeResources();
            LOG(INFO) << "Exiting handler thread to allow for join: " << misc_name;
            return;
        }

        LOG(INFO) << "Exiting handler thread and freeing resources: " << misc_name;

        if (handler->snapuserd()->IsAttached()) {
            handler->thread().detach();
        }

        // Important: free resources within the lock. This ensures that if
        // WaitForDelete() is called, the handler is either in the list, or
        // it's not and its resources are guaranteed to be freed.
        handler->FreeResources();
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

    JoinAllThreads();
    return true;
}

void SnapuserdServer::JoinAllThreads() {
    // Acquire the thread list within the lock.
    std::vector<std::shared_ptr<DmUserHandler>> dm_users;
    {
        std::lock_guard<std::mutex> guard(lock_);
        dm_users = std::move(dm_users_);
    }

    for (auto& client : dm_users) {
        auto& th = client->thread();

        if (th.joinable()) th.join();
    }
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

std::shared_ptr<DmUserHandler> SnapuserdServer::AddHandler(const std::string& misc_name,
                                                           const std::string& cow_device_path,
                                                           const std::string& backing_device) {
    auto snapuserd = std::make_shared<Snapuserd>(misc_name, cow_device_path, backing_device);
    if (!snapuserd->InitCowDevice()) {
        LOG(ERROR) << "Failed to initialize Snapuserd";
        return nullptr;
    }

    if (!snapuserd->InitializeWorkers()) {
        LOG(ERROR) << "Failed to initialize workers";
        return nullptr;
    }

    auto handler = std::make_shared<DmUserHandler>(snapuserd);
    {
        std::lock_guard<std::mutex> lock(lock_);
        if (FindHandler(&lock, misc_name) != dm_users_.end()) {
            LOG(ERROR) << "Handler already exists: " << misc_name;
            return nullptr;
        }
        dm_users_.push_back(handler);
    }
    return handler;
}

bool SnapuserdServer::StartHandler(const std::shared_ptr<DmUserHandler>& handler) {
    CHECK(!handler->snapuserd()->IsAttached());

    handler->snapuserd()->AttachControlDevice();

    handler->thread() = std::thread(std::bind(&SnapuserdServer::RunThread, this, handler));
    return true;
}

auto SnapuserdServer::FindHandler(std::lock_guard<std::mutex>* proof_of_lock,
                                  const std::string& misc_name) -> HandlerList::iterator {
    CHECK(proof_of_lock);

    for (auto iter = dm_users_.begin(); iter != dm_users_.end(); iter++) {
        if ((*iter)->misc_name() == misc_name) {
            return iter;
        }
    }
    return dm_users_.end();
}

bool SnapuserdServer::RemoveAndJoinHandler(const std::string& misc_name) {
    std::shared_ptr<DmUserHandler> handler;
    {
        std::lock_guard<std::mutex> lock(lock_);

        auto iter = FindHandler(&lock, misc_name);
        if (iter == dm_users_.end()) {
            // Client already deleted.
            return true;
        }
        handler = std::move(*iter);
        dm_users_.erase(iter);
    }

    auto& th = handler->thread();
    if (th.joinable()) {
        th.join();
    }
    return true;
}

}  // namespace snapshot
}  // namespace android
