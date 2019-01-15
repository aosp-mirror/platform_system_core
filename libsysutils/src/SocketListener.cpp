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

#define LOG_TAG "SocketListener"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <vector>

#include <cutils/sockets.h>
#include <log/log.h>
#include <sysutils/SocketListener.h>
#include <sysutils/SocketClient.h>

#define CtrlPipe_Shutdown 0
#define CtrlPipe_Wakeup   1

SocketListener::SocketListener(const char *socketName, bool listen) {
    init(socketName, -1, listen, false);
}

SocketListener::SocketListener(int socketFd, bool listen) {
    init(nullptr, socketFd, listen, false);
}

SocketListener::SocketListener(const char *socketName, bool listen, bool useCmdNum) {
    init(socketName, -1, listen, useCmdNum);
}

void SocketListener::init(const char *socketName, int socketFd, bool listen, bool useCmdNum) {
    mListen = listen;
    mSocketName = socketName;
    mSock = socketFd;
    mUseCmdNum = useCmdNum;
    pthread_mutex_init(&mClientsLock, nullptr);
}

SocketListener::~SocketListener() {
    if (mSocketName && mSock > -1)
        close(mSock);

    if (mCtrlPipe[0] != -1) {
        close(mCtrlPipe[0]);
        close(mCtrlPipe[1]);
    }
    for (auto pair : mClients) {
        pair.second->decRef();
    }
}

int SocketListener::startListener() {
    return startListener(4);
}

int SocketListener::startListener(int backlog) {

    if (!mSocketName && mSock == -1) {
        SLOGE("Failed to start unbound listener");
        errno = EINVAL;
        return -1;
    } else if (mSocketName) {
        if ((mSock = android_get_control_socket(mSocketName)) < 0) {
            SLOGE("Obtaining file descriptor socket '%s' failed: %s",
                 mSocketName, strerror(errno));
            return -1;
        }
        SLOGV("got mSock = %d for %s", mSock, mSocketName);
        fcntl(mSock, F_SETFD, FD_CLOEXEC);
    }

    if (mListen && listen(mSock, backlog) < 0) {
        SLOGE("Unable to listen on socket (%s)", strerror(errno));
        return -1;
    } else if (!mListen)
        mClients[mSock] = new SocketClient(mSock, false, mUseCmdNum);

    if (pipe(mCtrlPipe)) {
        SLOGE("pipe failed (%s)", strerror(errno));
        return -1;
    }

    if (pthread_create(&mThread, nullptr, SocketListener::threadStart, this)) {
        SLOGE("pthread_create (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

int SocketListener::stopListener() {
    char c = CtrlPipe_Shutdown;
    int  rc;

    rc = TEMP_FAILURE_RETRY(write(mCtrlPipe[1], &c, 1));
    if (rc != 1) {
        SLOGE("Error writing to control pipe (%s)", strerror(errno));
        return -1;
    }

    void *ret;
    if (pthread_join(mThread, &ret)) {
        SLOGE("Error joining to listener thread (%s)", strerror(errno));
        return -1;
    }
    close(mCtrlPipe[0]);
    close(mCtrlPipe[1]);
    mCtrlPipe[0] = -1;
    mCtrlPipe[1] = -1;

    if (mSocketName && mSock > -1) {
        close(mSock);
        mSock = -1;
    }

    for (auto pair : mClients) {
        delete pair.second;
    }
    mClients.clear();
    return 0;
}

void *SocketListener::threadStart(void *obj) {
    SocketListener *me = reinterpret_cast<SocketListener *>(obj);

    me->runListener();
    pthread_exit(nullptr);
    return nullptr;
}

void SocketListener::runListener() {
    while (true) {
        std::vector<pollfd> fds;

        pthread_mutex_lock(&mClientsLock);
        fds.reserve(2 + mClients.size());
        fds.push_back({.fd = mCtrlPipe[0], .events = POLLIN});
        if (mListen) fds.push_back({.fd = mSock, .events = POLLIN});
        for (auto pair : mClients) {
            // NB: calling out to an other object with mClientsLock held (safe)
            const int fd = pair.second->getSocket();
            if (fd != pair.first) SLOGE("fd mismatch: %d != %d", fd, pair.first);
            fds.push_back({.fd = fd, .events = POLLIN});
        }
        pthread_mutex_unlock(&mClientsLock);

        SLOGV("mListen=%d, mSocketName=%s", mListen, mSocketName);
        int rc = TEMP_FAILURE_RETRY(poll(fds.data(), fds.size(), -1));
        if (rc < 0) {
            SLOGE("poll failed (%s) mListen=%d", strerror(errno), mListen);
            sleep(1);
            continue;
        }

        if (fds[0].revents & (POLLIN | POLLERR)) {
            char c = CtrlPipe_Shutdown;
            TEMP_FAILURE_RETRY(read(mCtrlPipe[0], &c, 1));
            if (c == CtrlPipe_Shutdown) {
                break;
            }
            continue;
        }
        if (mListen && (fds[1].revents & (POLLIN | POLLERR))) {
            int c = TEMP_FAILURE_RETRY(accept4(mSock, nullptr, nullptr, SOCK_CLOEXEC));
            if (c < 0) {
                SLOGE("accept failed (%s)", strerror(errno));
                sleep(1);
                continue;
            }
            pthread_mutex_lock(&mClientsLock);
            mClients[c] = new SocketClient(c, true, mUseCmdNum);
            pthread_mutex_unlock(&mClientsLock);
        }

        // Add all active clients to the pending list first, so we can release
        // the lock before invoking the callbacks.
        std::vector<SocketClient*> pending;
        pthread_mutex_lock(&mClientsLock);
        const int size = fds.size();
        for (int i = mListen ? 2 : 1; i < size; ++i) {
            const struct pollfd& p = fds[i];
            if (p.revents & (POLLIN | POLLERR)) {
                auto it = mClients.find(p.fd);
                if (it == mClients.end()) {
                    SLOGE("fd vanished: %d", p.fd);
                    continue;
                }
                SocketClient* c = it->second;
                pending.push_back(c);
                c->incRef();
            }
        }
        pthread_mutex_unlock(&mClientsLock);

        for (SocketClient* c : pending) {
            // Process it, if false is returned, remove from the map
            SLOGV("processing fd %d", c->getSocket());
            if (!onDataAvailable(c)) {
                release(c, false);
            }
            c->decRef();
        }
    }
}

bool SocketListener::release(SocketClient* c, bool wakeup) {
    bool ret = false;
    /* if our sockets are connection-based, remove and destroy it */
    if (mListen && c) {
        /* Remove the client from our map */
        SLOGV("going to zap %d for %s", c->getSocket(), mSocketName);
        pthread_mutex_lock(&mClientsLock);
        ret = (mClients.erase(c->getSocket()) != 0);
        pthread_mutex_unlock(&mClientsLock);
        if (ret) {
            ret = c->decRef();
            if (wakeup) {
                char b = CtrlPipe_Wakeup;
                TEMP_FAILURE_RETRY(write(mCtrlPipe[1], &b, 1));
            }
        }
    }
    return ret;
}

std::vector<SocketClient*> SocketListener::snapshotClients() {
    std::vector<SocketClient*> clients;
    pthread_mutex_lock(&mClientsLock);
    clients.reserve(mClients.size());
    for (auto pair : mClients) {
        SocketClient* c = pair.second;
        c->incRef();
        clients.push_back(c);
    }
    pthread_mutex_unlock(&mClientsLock);

    return clients;
}

void SocketListener::sendBroadcast(int code, const char *msg, bool addErrno) {
    for (SocketClient* c : snapshotClients()) {
        // broadcasts are unsolicited and should not include a cmd number
        if (c->sendMsg(code, msg, addErrno, false)) {
            SLOGW("Error sending broadcast (%s)", strerror(errno));
        }
        c->decRef();
    }
}

void SocketListener::runOnEachSocket(SocketClientCommand *command) {
    for (SocketClient* c : snapshotClients()) {
        command->runSocketCommand(c);
        c->decRef();
    }
}
