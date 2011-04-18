/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <string.h>

#define LOG_TAG "NetlinkListener"
#include <cutils/log.h>

#include <sysutils/NetlinkListener.h>
#include <sysutils/NetlinkEvent.h>

NetlinkListener::NetlinkListener(int socket) :
                            SocketListener(socket, false) {
}

bool NetlinkListener::onDataAvailable(SocketClient *cli)
{
    int socket = cli->getSocket();
    ssize_t count;
    char cred_msg[CMSG_SPACE(sizeof(struct ucred))];
    struct sockaddr_nl snl;
    struct iovec iov = {mBuffer, sizeof(mBuffer)};
    struct msghdr hdr = {&snl, sizeof(snl), &iov, 1, cred_msg, sizeof(cred_msg), 0};

    if ((count = recvmsg(socket, &hdr, 0)) < 0) {
        SLOGE("recvmsg failed (%s)", strerror(errno));
        return false;
    }

    if ((snl.nl_groups != 1) || (snl.nl_pid != 0)) {
        SLOGE("ignoring non-kernel netlink multicast message");
        return false;
    }

    struct cmsghdr * cmsg = CMSG_FIRSTHDR(&hdr);

    if (cmsg == NULL || cmsg->cmsg_type != SCM_CREDENTIALS) {
        SLOGE("ignoring message with no sender credentials");
        return false;
    }

    struct ucred * cred = (struct ucred *)CMSG_DATA(cmsg);
    if (cred->uid != 0) {
        SLOGE("ignoring message from non-root UID %d", cred->uid);
        return false;
    }

    NetlinkEvent *evt = new NetlinkEvent();
    if (!evt->decode(mBuffer, count)) {
        SLOGE("Error decoding NetlinkEvent");
        goto out;
    }

    onEvent(evt);
out:
    delete evt;
    return true;
}
