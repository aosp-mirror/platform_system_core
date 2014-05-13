/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include "FwmarkClient.h"
#include "netd_client/FwmarkCommands.h"

#include <sys/socket.h>
#include <unistd.h>

#define CLOSE_FD_AND_RESTORE_ERRNO(fd) \
    do { \
        int error = errno; \
        close(fd); \
        errno = error; \
    } while (0)

namespace {

typedef int (*ConnectFunctionType)(int, const sockaddr*, socklen_t);
typedef int (*AcceptFunctionType)(int, sockaddr*, socklen_t*);

ConnectFunctionType libcConnect = 0;
AcceptFunctionType libcAccept = 0;

int netdClientConnect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    if (FwmarkClient::shouldSetFwmark(sockfd, addr)) {
        char data[] = {FWMARK_COMMAND_ON_CONNECT};
        if (!FwmarkClient().send(data, sizeof(data), sockfd)) {
            return -1;
        }
    }
    return libcConnect(sockfd, addr, addrlen);
}

int netdClientAccept(int sockfd, sockaddr* addr, socklen_t* addrlen) {
    int acceptedSocket = libcAccept(sockfd, addr, addrlen);
    if (acceptedSocket == -1) {
        return -1;
    }
    sockaddr socketAddress;
    if (!addr) {
        socklen_t socketAddressLen = sizeof(socketAddress);
        if (getsockname(acceptedSocket, &socketAddress, &socketAddressLen) == -1) {
            CLOSE_FD_AND_RESTORE_ERRNO(acceptedSocket);
            return -1;
        }
        addr = &socketAddress;
    }
    if (FwmarkClient::shouldSetFwmark(acceptedSocket, addr)) {
        char data[] = {FWMARK_COMMAND_ON_ACCEPT};
        if (!FwmarkClient().send(data, sizeof(data), acceptedSocket)) {
            CLOSE_FD_AND_RESTORE_ERRNO(acceptedSocket);
            return -1;
        }
    }
    return acceptedSocket;
}

}  // namespace

extern "C" void netdClientInitConnect(ConnectFunctionType* function) {
    if (function && *function) {
        libcConnect = *function;
        *function = netdClientConnect;
    }
}

extern "C" void netdClientInitAccept(AcceptFunctionType* function) {
    if (function && *function) {
        libcAccept = *function;
        *function = netdClientAccept;
    }
}
