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
#include <sysutils/SocketClient.h>

SocketListener::SocketListener(const char *socketName, bool listen) {
    mListen = listen;
    mSocketName = socketName;
    mSock = -1;
    pthread_mutex_init(&mClientsLock, NULL);
    mClients = new SocketClientCollection();
}

SocketListener::SocketListener(int socketFd, bool listen) {
    mListen = listen;
    mSocketName = NULL;
    mSock = socketFd;
    pthread_mutex_init(&mClientsLock, NULL);
    mClients = new SocketClientCollection();
}

SocketListener::~SocketListener() {
    if (mSocketName && mSock > -1)
        close(mSock);

    if (mCtrlPipe[0] != -1) {
        close(mCtrlPipe[0]);
        close(mCtrlPipe[1]);
    }
    SocketClientCollection::iterator it;
    for (it = mClients->begin(); it != mClients->end();) {
        delete (*it);
        it = mClients->erase(it);
    }
    delete mClients;
}

int SocketListener::startListener() {

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
    }

    if (mListen && listen(mSock, 4) < 0) {
        SLOGE("Unable to listen on socket (%s)", strerror(errno));
        return -1;
    } else if (!mListen)
        mClients->push_back(new SocketClient(mSock));

    if (pipe(mCtrlPipe)) {
        SLOGE("pipe failed (%s)", strerror(errno));
        return -1;
    }

    if (pthread_create(&mThread, NULL, SocketListener::threadStart, this)) {
        SLOGE("pthread_create (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

int SocketListener::stopListener() {
    char c = 0;
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

    SocketClientCollection::iterator it;
    for (it = mClients->begin(); it != mClients->end();) {
        delete (*it);
        it = mClients->erase(it);
    }
    return 0;
}

void *SocketListener::threadStart(void *obj) {
    SocketListener *me = reinterpret_cast<SocketListener *>(obj);

    me->runListener();
    pthread_exit(NULL);
    return NULL;
}

void SocketListener::runListener() {

    SocketClientCollection *pendingList = new SocketClientCollection();

    while(1) {
        SocketClientCollection::iterator it;
        fd_set read_fds;
        int rc = 0;
        int max = -1;

        FD_ZERO(&read_fds);

        if (mListen) {
            max = mSock;
            FD_SET(mSock, &read_fds);
        }

        FD_SET(mCtrlPipe[0], &read_fds);
        if (mCtrlPipe[0] > max)
            max = mCtrlPipe[0];

        pthread_mutex_lock(&mClientsLock);
        for (it = mClients->begin(); it != mClients->end(); ++it) {
            int fd = (*it)->getSocket();
            FD_SET(fd, &read_fds);
            if (fd > max)
                max = fd;
        }
        pthread_mutex_unlock(&mClientsLock);

        if ((rc = select(max + 1, &read_fds, NULL, NULL, NULL)) < 0) {
            if (errno == EINTR)
                continue;
            SLOGE("select failed (%s)", strerror(errno));
            sleep(1);
            continue;
        } else if (!rc)
            continue;

        if (FD_ISSET(mCtrlPipe[0], &read_fds))
            break;
        if (mListen && FD_ISSET(mSock, &read_fds)) {
            struct sockaddr addr;
            socklen_t alen;
            int c;

            do {
                alen = sizeof(addr);
                c = accept(mSock, &addr, &alen);
            } while (c < 0 && errno == EINTR);
            if (c < 0) {
                SLOGE("accept failed (%s)", strerror(errno));
                sleep(1);
                continue;
            }
            pthread_mutex_lock(&mClientsLock);
            mClients->push_back(new SocketClient(c));
            pthread_mutex_unlock(&mClientsLock);
        }

        /* Add all active clients to the pending list first */
        pendingList->clear();
        pthread_mutex_lock(&mClientsLock);
        for (it = mClients->begin(); it != mClients->end(); ++it) {
            int fd = (*it)->getSocket();
            if (FD_ISSET(fd, &read_fds)) {
                pendingList->push_back(*it);
            }
        }
        pthread_mutex_unlock(&mClientsLock);

        /* Process the pending list, since it is owned by the thread,
         * there is no need to lock it */
        while (!pendingList->empty()) {
            /* Pop the first item from the list */
            it = pendingList->begin();
            SocketClient* c = *it;
            pendingList->erase(it);
            /* Process it, if false is returned, remove and destroy it */
            if (!onDataAvailable(c)) {
                /* Remove the client from our array */
                pthread_mutex_lock(&mClientsLock);
                for (it = mClients->begin(); it != mClients->end(); ++it) {
                    if (*it == c) {
                        mClients->erase(it);
                        break;
                    }
                }
                pthread_mutex_unlock(&mClientsLock);
                /* Destroy the client */
                close(c->getSocket());
                delete c;
            }
        }
    }
    delete pendingList;
}

void SocketListener::sendBroadcast(int code, const char *msg, bool addErrno) {
    pthread_mutex_lock(&mClientsLock);
    SocketClientCollection::iterator i;

    for (i = mClients->begin(); i != mClients->end(); ++i) {
        if ((*i)->sendMsg(code, msg, addErrno)) {
            SLOGW("Error sending broadcast (%s)", strerror(errno));
        }
    }
    pthread_mutex_unlock(&mClientsLock);
}

void SocketListener::sendBroadcast(const char *msg) {
    pthread_mutex_lock(&mClientsLock);
    SocketClientCollection::iterator i;

    for (i = mClients->begin(); i != mClients->end(); ++i) {
        if ((*i)->sendMsg(msg)) {
            SLOGW("Error sending broadcast (%s)", strerror(errno));
        }
    }
    pthread_mutex_unlock(&mClientsLock);
}
