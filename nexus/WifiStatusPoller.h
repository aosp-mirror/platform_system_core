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

#ifndef _WIFI_STATUS_POLLER_H
#define _WIFI_STATUS_POLLER_H

#include <pthread.h>

class IWifiStatusPollerHandler;

class WifiStatusPoller {
    pthread_t                mThread;
    int                      mCtrlPipe[2];
    int                      mPollingInterval;
    IWifiStatusPollerHandler *mHandlers;
    bool                     mStarted;

public:
    WifiStatusPoller(IWifiStatusPollerHandler *handler);
    virtual ~WifiStatusPoller() {}

    int start();
    int stop();
    bool isStarted() { return mStarted; }

    void setPollingInterval(int interval);
    int getPollingInterval() { return mPollingInterval; }
    
private:
    static void *threadStart(void *obj);
    void run();
};

#endif
