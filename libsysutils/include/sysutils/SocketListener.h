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
#ifndef _SOCKETLISTENER_H
#define _SOCKETLISTENER_H

#include <pthread.h>

#include <unordered_map>
#include <vector>

#include <sysutils/SocketClient.h>
#include "SocketClientCommand.h"

class SocketListener {
    bool                    mListen;
    const char              *mSocketName;
    int                     mSock;
    std::unordered_map<int, SocketClient*> mClients;
    pthread_mutex_t         mClientsLock;
    int                     mCtrlPipe[2];
    pthread_t               mThread;
    bool                    mUseCmdNum;

public:
    SocketListener(const char *socketName, bool listen);
    SocketListener(const char *socketName, bool listen, bool useCmdNum);
    SocketListener(int socketFd, bool listen);

    virtual ~SocketListener();
    int startListener();
    int startListener(int backlog);
    int stopListener();

    void sendBroadcast(int code, const char *msg, bool addErrno);

    void runOnEachSocket(SocketClientCommand *command);

    bool release(SocketClient *c) { return release(c, true); }

protected:
    virtual bool onDataAvailable(SocketClient *c) = 0;

private:
    static void *threadStart(void *obj);

    // Add all clients to a separate list, so we don't have to hold the lock
    // while processing it.
    std::vector<SocketClient*> snapshotClients();

    bool release(SocketClient *c, bool wakeup);
    void runListener();
    void init(const char *socketName, int socketFd, bool listen, bool useCmdNum);
};
#endif
