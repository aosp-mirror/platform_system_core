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
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#define LOG_TAG "SocketListener"
#include <cutils/log.h>

#include <cutils/sockets.h>

#include <sysutils/SocketListener.h>

SocketListener::SocketListener(const char *socketName, bool acceptClients) {
    mAcceptClients = acceptClients;
    mCsock = -1;
    mSocketName = socketName;
    mSock = -1;
}

SocketListener::SocketListener(int socketFd, bool acceptClients) {
    mAcceptClients = acceptClients;
    mCsock = -1;
    mSocketName = NULL;
    mSock = socketFd;
}

int SocketListener::run() {

    if (!mSocketName && mSock == -1) {
        errno = EINVAL;
        return -1;
    } else if (mSocketName) {
        if ((mSock = android_get_control_socket(mSocketName)) < 0) {
            LOGE("Obtaining file descriptor socket '%s' failed: %s",
                 mSocketName, strerror(errno));
            return -1;
        }
    }

    if (mAcceptClients) {
        if (listen(mSock, 4) < 0) {
            LOGE("Unable to listen on socket (%s)", strerror(errno));
            return -1;
        }
    }

    while(1) {
        fd_set read_fds;
        struct timeval to;
        int max = 0;
        int rc = 0;

        to.tv_sec = 60 * 60;
        to.tv_usec = 0;

        FD_ZERO(&read_fds);

        if ((mAcceptClients == false) ||
            (mAcceptClients == true && mCsock == -1)) {
            FD_SET(mSock, &read_fds);
            max = mSock;
        } else if (mCsock != -1) {
            FD_SET(mCsock, &read_fds);
            max = mCsock;
        }

        if ((rc = select(max + 1, &read_fds, NULL, NULL, &to)) < 0) {
            LOGE("select failed (%s)", strerror(errno));
            return -errno;
        } else if (!rc)
            continue;
        else if (FD_ISSET(mSock, &read_fds)) {
            /*
             * If we're accepting client connections then 
             * accept and gobble the event. Otherwise
             * pass it on to the handlers.
             */
            if (mAcceptClients) {
                struct sockaddr addr;
                socklen_t alen = sizeof(addr);

                if ((mCsock = accept(mSock, &addr, &alen)) < 0) {
                    LOGE("accept failed (%s)", strerror(errno));
                    return -errno;
                }
                LOGD("SocketListener client connection accepted");
            } else if (!onDataAvailable(mSock)) {
                LOGW("SocketListener closing listening socket (Will shut down)");
                close(mSock);
                return -ESHUTDOWN;
            }
        } else if ((FD_ISSET(mCsock, &read_fds)) &&
                   !onDataAvailable(mCsock)) {
                /*
                 * Once mCsock == -1, we'll start
                 * accepting connections on mSock again.
                 */
                LOGD("SocketListener closing client socket");
                close(mCsock);
                mCsock = -1;
            }
    }
    return 0;
}

bool SocketListener::onDataAvailable(int socket) {
    return false;
}
