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

namespace {

typedef int (*ConnectFunctionType)(int, const sockaddr*, socklen_t);

ConnectFunctionType libcConnect = 0;

int netdClientConnect(int sockfd, const sockaddr* addr, socklen_t addrlen) {
    if (FwmarkClient::shouldSetFwmark(sockfd, addr)) {
        char data[] = {FWMARK_COMMAND_ON_CONNECT};
        if (!FwmarkClient().send(data, sizeof(data), sockfd)) {
            return -1;
        }
    }
    return libcConnect(sockfd, addr, addrlen);
}

}  // namespace

extern "C" void netdClientInitConnect(ConnectFunctionType* function) {
    if (function && *function) {
        libcConnect = *function;
        *function = netdClientConnect;
    }
}
