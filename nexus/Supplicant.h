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
#ifndef _SUPPLICANT_H
#define _SUPPLICANT_H

struct wpa_ctrl;
class SupplicantListener;
class SupplicantEvent;

#include <pthread.h>

#include "ScanResult.h"

class Supplicant {
private:
    struct wpa_ctrl      *mCtrl;
    struct wpa_ctrl      *mMonitor;
    SupplicantListener   *mListener;
    int                  mState;

    ScanResultCollection *mLatestScanResults;
    pthread_mutex_t      mLatestScanResultsLock;
  
public:
    Supplicant();
    virtual ~Supplicant() {}

    int start();
    int stop();
    bool isStarted();
    int triggerScan(bool active);

    ScanResultCollection *createLatestScanResults();
    WifiNetworkCollection *createWifiNetworkList();


    int getState() { return mState; }


// XXX: Extract these into an interface
// handlers for SupplicantListener
public:
    virtual int onConnectedEvent(SupplicantEvent *evt);
    virtual int onDisconnectedEvent(SupplicantEvent *evt);
    virtual int onTerminatingEvent(SupplicantEvent *evt);
    virtual int onPasswordChangedEvent(SupplicantEvent *evt);
    virtual int onEapNotificationEvent(SupplicantEvent *evt);
    virtual int onEapStartedEvent(SupplicantEvent *evt);
    virtual int onEapMethodEvent(SupplicantEvent *evt);
    virtual int onEapSuccessEvent(SupplicantEvent *evt);
    virtual int onEapFailureEvent(SupplicantEvent *evt);
    virtual int onScanResultsEvent(SupplicantEvent *evt);
    virtual int onStateChangeEvent(SupplicantEvent *evt);
    virtual int onLinkSpeedEvent(SupplicantEvent *evt);
    virtual int onDriverStateEvent(SupplicantEvent *evt);

private:
    int connectToSupplicant();
    int sendCommand(const char *cmd, char *reply, size_t *reply_len);
    int setupConfig();
};

#endif
