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

#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace {

const sockaddr_un FWMARK_SERVER_PATH = {AF_UNIX, "/dev/socket/fwmarkd"};

}  // namespace

bool FwmarkClient::shouldSetFwmark(int sockfd, const sockaddr* addr) {
    return sockfd >= 0 && addr && (addr->sa_family == AF_INET || addr->sa_family == AF_INET6) &&
           !getenv("ANDROID_NO_USE_FWMARK_CLIENT");
}

FwmarkClient::FwmarkClient() : mChannel(-1) {
}

FwmarkClient::~FwmarkClient() {
    if (mChannel >= 0) {
        // We don't care about errors while closing the channel, so restore any previous error.
        int error = errno;
        close(mChannel);
        errno = error;
    }
}

bool FwmarkClient::send(void* data, size_t len, int fd) {
    mChannel = socket(AF_UNIX, SOCK_STREAM, 0);
    if (mChannel == -1) {
        return false;
    }

    if (TEMP_FAILURE_RETRY(connect(mChannel, reinterpret_cast<const sockaddr*>(&FWMARK_SERVER_PATH),
                                   sizeof(FWMARK_SERVER_PATH))) == -1) {
        // If we are unable to connect to the fwmark server, assume there's no error. This protects
        // against future changes if the fwmark server goes away.
        errno = 0;
        return true;
    }

    iovec iov;
    iov.iov_base = data;
    iov.iov_len = len;

    msghdr message;
    memset(&message, 0, sizeof(message));
    message.msg_iov = &iov;
    message.msg_iovlen = 1;

    union {
        cmsghdr cmh;
        char cmsg[CMSG_SPACE(sizeof(fd))];
    } cmsgu;

    memset(cmsgu.cmsg, 0, sizeof(cmsgu.cmsg));
    message.msg_control = cmsgu.cmsg;
    message.msg_controllen = sizeof(cmsgu.cmsg);

    cmsghdr* const cmsgh = CMSG_FIRSTHDR(&message);
    cmsgh->cmsg_len = CMSG_LEN(sizeof(fd));
    cmsgh->cmsg_level = SOL_SOCKET;
    cmsgh->cmsg_type = SCM_RIGHTS;
    memcpy(CMSG_DATA(cmsgh), &fd, sizeof(fd));

    if (TEMP_FAILURE_RETRY(sendmsg(mChannel, &message, 0)) == -1) {
        return false;
    }

    int error = 0;
    if (TEMP_FAILURE_RETRY(recv(mChannel, &error, sizeof(error), 0)) == -1) {
        return false;
    }

    errno = error;
    return !error;
}
