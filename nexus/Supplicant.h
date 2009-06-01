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
class ServiceManager;
class PropertyManager;
class Controller;
class WifiController;

#include <pthread.h>

#include "ScanResult.h"
#include "WifiNetwork.h"
#include "IPropertyProvider.h"

class Supplicant : public IPropertyProvider {
private:
    struct wpa_ctrl      *mCtrl;
    struct wpa_ctrl      *mMonitor;
    SupplicantListener   *mListener;
    int                  mState;
    ServiceManager       *mServiceManager;
    PropertyManager      *mPropMngr;
    WifiController       *mController;
    char                 *mInterfaceName;

    ScanResultCollection *mLatestScanResults;
    pthread_mutex_t      mLatestScanResultsLock;

    WifiNetworkCollection *mNetworks;
    pthread_mutex_t        mNetworksLock;
 
public:
    Supplicant(WifiController *wc, PropertyManager *propmngr);
    virtual ~Supplicant();

    int start();
    int stop();
    bool isStarted();

    int triggerScan(bool active);
    ScanResultCollection *createLatestScanResults();

    WifiNetwork *createNetwork();
    WifiNetwork *lookupNetwork(int networkId);
    int removeNetwork(WifiNetwork *net);
    WifiNetworkCollection *createNetworkList();
    int refreshNetworkList();

    int setNetworkVar(int networkId, const char *var, const char *value);
    const char *getNetworkVar(int networkid, const char *var, char *buffer,
                              size_t max);
    int enableNetwork(int networkId, bool enabled);

    int getState() { return mState; }
    Controller *getController() { return (Controller *) mController; }
    const char *getInterfaceName() { return mInterfaceName; }

    int set(const char *name, const char *value);
    const char *get(const char *name, char *buffer, size_t max);

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
    int retrieveInterfaceName();
};

#endif
