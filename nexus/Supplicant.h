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
class ServiceManager;
class Controller;
class WifiController;
class SupplicantStatus;

#include <pthread.h>

#include "WifiNetwork.h"
#include "ISupplicantEventHandler.h"

class Supplicant {
    struct wpa_ctrl      *mCtrl;
    struct wpa_ctrl      *mMonitor;
    SupplicantListener   *mListener;
    ServiceManager       *mServiceManager;
    WifiController       *mController;
    char                 *mInterfaceName;

    WifiNetworkCollection   *mNetworks;
    pthread_mutex_t         mNetworksLock;
    ISupplicantEventHandler *mHandlers;
 
public:
    Supplicant(WifiController *wc, ISupplicantEventHandler *handlers);
    virtual ~Supplicant();

    int start();
    int stop();
    bool isStarted();

    int setScanMode(bool active);
    int triggerScan();

    WifiNetwork *createNetwork();
    WifiNetwork *lookupNetwork(int networkId);
    int removeNetwork(WifiNetwork *net);
    WifiNetworkCollection *createNetworkList();
    int refreshNetworkList();

    int setNetworkVar(int networkId, const char *var, const char *value);
    const char *getNetworkVar(int networkid, const char *var, char *buffer,
                              size_t max);
    int enableNetwork(int networkId, bool enabled);

    int disconnect();
    int reconnect();
    int reassociate();
    int setApScanMode(int mode);
    int enablePacketFilter();
    int disablePacketFilter();
    int setBluetoothCoexistenceMode(int mode);
    int enableBluetoothCoexistenceScan();
    int disableBluetoothCoexistenceScan();
    int stopDriver();
    int startDriver();
    int getRssi(int *buffer);
    int getLinkSpeed();
    int getNetworkCount();

    SupplicantStatus *getStatus();

    Controller *getController() { return (Controller *) mController; }
    const char *getInterfaceName() { return mInterfaceName; }

    int sendCommand(const char *cmd, char *reply, size_t *reply_len);

private:
    int connectToSupplicant();
    int setupConfig();
    int retrieveInterfaceName();
    WifiNetwork *lookupNetwork_UNLOCKED(int networkId);
};

#endif
