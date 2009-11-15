
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

#ifndef _DhcpClient_H
#define _DhcpClient_H

#include <pthread.h>

class IDhcpEventHandlers;
class ServiceManager;
class DhcpListener;
class Controller;

class DhcpClient {
public:
    static const int STATUS_MONITOR_PORT = 6666;

private:
    int                mState;
    IDhcpEventHandlers *mHandlers;
    ServiceManager     *mServiceManager;
    DhcpListener       *mListener;
    int                mListenerSocket;
    pthread_mutex_t    mLock;
    Controller         *mController;
    bool               mDoArpProbe;

public:
    DhcpClient(IDhcpEventHandlers *handlers);
    virtual ~DhcpClient();

    int getState() { return mState; }
    bool getDoArpProbe() { return mDoArpProbe; }
    void setDoArpProbe(bool probe);

    int start(Controller *c);
    int stop();
};

#endif
