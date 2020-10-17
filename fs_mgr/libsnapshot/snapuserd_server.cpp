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
    if (input == "terminate-request") return DaemonOperations::TERMINATING;
    if (input == "query") return DaemonOperations::QUERY;

    return DaemonOperations::INVALID;
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

// new thread
void SnapuserdServer::ThreadStart(std::string cow_device, std::string backing_device,
                                  std::string control_device) {
    Snapuserd snapd(cow_device, backing_device, control_device);
    if (!snapd.Init()) {
        PLOG(ERROR) << "Snapuserd: Init failed";
        return;
    }

    while (StopRequested() == false) {
        int ret = snapd.Run();

        if (ret < 0) {
            LOG(ERROR) << "Snapuserd: Thread terminating as control device is de-registered";
            break;
        }
    }
}

void SnapuserdServer::ShutdownThreads() {
    StopThreads();

    for (auto& client : clients_vec_) {
        auto& th = client->GetThreadHandler();

        if (th->joinable()) th->join();
    }
}

int SnapuserdServer::Sendmsg(int fd, char* msg, size_t size) {
    int ret = TEMP_FAILURE_RETRY(send(fd, (char*)msg, size, 0));
    if (ret < 0) {
        PLOG(ERROR) << "Snapuserd:server: send() failed";
        return -1;
    }

    if (ret < size) {
        PLOG(ERROR) << "Partial data sent";
        return -1;
    }

    return 0;
}

std::string SnapuserdServer::Recvmsg(int fd, int* ret) {
    struct timeval tv;
    fd_set set;
    char msg[MAX_PACKET_SIZE];

    tv.tv_sec = 2;
    tv.tv_usec = 0;
    FD_ZERO(&set);
    FD_SET(fd, &set);
    *ret = select(fd + 1, &set, NULL, NULL, &tv);
    if (*ret == -1) {  // select failed
        return {};
    } else if (*ret == 0) {  // timeout
        return {};
    } else {
        *ret = TEMP_FAILURE_RETRY(recv(fd, msg, MAX_PACKET_SIZE, 0));
        if (*ret < 0) {
            PLOG(ERROR) << "Snapuserd:server: recv failed";
            return {};
        } else if (*ret == 0) {
            LOG(DEBUG) << "Snapuserd client disconnected";
            return {};
        } else {
            std::string str(msg);
            return str;
        }
    }
}

int SnapuserdServer::Receivemsg(int fd) {
    char msg[MAX_PACKET_SIZE];
    std::unique_ptr<Client> newClient;
    int ret = 0;

    while (1) {
        memset(msg, '\0', MAX_PACKET_SIZE);
        std::string str = Recvmsg(fd, &ret);

        if (ret <= 0) {
            LOG(DEBUG) << "recv failed with ret: " << ret;
            return 0;
        }

        const char delim = ',';

        std::vector<std::string> out;
        Parsemsg(str, delim, out);
        DaemonOperations op = Resolveop(out[0]);
        memset(msg, '\0', MAX_PACKET_SIZE);

        switch (op) {
            case DaemonOperations::START: {
                // Message format:
                // start,<cow_device_path>,<source_device_path>,<control_device>
                //
                // Start the new thread which binds to dm-user misc device
                newClient = std::make_unique<Client>();
                newClient->SetThreadHandler(
                        std::bind(&SnapuserdServer::ThreadStart, this, out[1], out[2], out[3]));
                clients_vec_.push_back(std::move(newClient));
                sprintf(msg, "success");
                Sendmsg(fd, msg, MAX_PACKET_SIZE);
                return 0;
            }
            case DaemonOperations::STOP: {
                // Message format: stop
                //
                // Stop all the threads gracefully and then shutdown the
                // main thread
                ShutdownThreads();
                return static_cast<int>(DaemonOperations::STOP);
            }
            case DaemonOperations::TERMINATING: {
                // Message format: terminate-request
                //
                // This is invoked during transition. First stage
                // daemon will receive this request. First stage daemon
                // will be considered as a passive daemon from hereon.
                SetTerminating();
                sprintf(msg, "success");
                Sendmsg(fd, msg, MAX_PACKET_SIZE);
                return 0;
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
                std::string dstr = GetDaemonStatus();
                memcpy(msg, dstr.c_str(), dstr.size());
                Sendmsg(fd, msg, MAX_PACKET_SIZE);
                if (dstr == "active")
                    break;
                else
                    return 0;
            }
            default: {
                sprintf(msg, "fail");
                Sendmsg(fd, msg, MAX_PACKET_SIZE);
                return 0;
            }
        }
    }
}

int SnapuserdServer::Start(std::string socketname) {
    sockfd_.reset(socket_local_server(socketname.c_str(), ANDROID_SOCKET_NAMESPACE_RESERVED,
                                      SOCK_STREAM));
    if (sockfd_ < 0) {
        PLOG(ERROR) << "Failed to create server socket " << socketname;
        return -1;
    }

    LOG(DEBUG) << "Snapuserd server successfully started with socket name " << socketname;
    return 0;
}

int SnapuserdServer::AcceptClient() {
    int fd = accept(sockfd_.get(), NULL, NULL);
    if (fd < 0) {
        PLOG(ERROR) << "Socket accept failed: " << strerror(errno);
        return -1;
    }

    return Receivemsg(fd);
}

}  // namespace snapshot
}  // namespace android
