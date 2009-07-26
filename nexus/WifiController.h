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

#ifndef _WIFI_CONTROLLER_H
#define _WIFI_CONTROLLER_H

#include <sys/types.h>

#include "Controller.h"
#include "ScanResult.h"
#include "WifiNetwork.h"
#include "ISupplicantEventHandler.h"

class NetInterface;
class Supplicant;
class WifiScanner;
class SupplicantAssociatingEvent;
class SupplicantAssociatedEvent;
class SupplicantConnectedEvent;
class SupplicantScanResultsEvent;
class SupplicantStateChangeEvent;
class SupplicantDisconnectedEvent;

class WifiController : public Controller, public ISupplicantEventHandler {
public:
    static const uint32_t SCAN_ENABLE_MASK       = 0x01;
    static const uint32_t SCAN_ACTIVE_MASK       = 0x02;
    static const uint32_t SCAN_REPEAT_MASK       = 0x04;

    static const uint32_t SCANMODE_NONE               = 0;
    static const uint32_t SCANMODE_PASSIVE_ONESHOT    = SCAN_ENABLE_MASK;
    static const uint32_t SCANMODE_PASSIVE_CONTINUOUS = SCAN_ENABLE_MASK | SCAN_REPEAT_MASK;
    static const uint32_t SCANMODE_ACTIVE_ONESHOT     = SCAN_ENABLE_MASK | SCAN_ACTIVE_MASK;
    static const uint32_t SCANMODE_ACTIVE_CONTINUOUS  = SCAN_ENABLE_MASK | SCAN_ACTIVE_MASK | SCAN_REPEAT_MASK;

private:
    Supplicant *mSupplicant;
    char        mModulePath[255];
    char        mModuleName[64];
    char        mModuleArgs[255];

    uint32_t    mCurrentScanMode;
    WifiScanner *mScanner;
    int         mSupplicantState;

    ScanResultCollection *mLatestScanResults;
    pthread_mutex_t      mLatestScanResultsLock;

    bool        mEnabled;

public:
    WifiController(PropertyManager *propmngr, IControllerHandler *handlers, char *modpath, char *modname, char *modargs);
    virtual ~WifiController() {}

    int start();
    int stop();

    WifiNetwork *createNetwork();
    int removeNetwork(int networkId);
    WifiNetworkCollection *createNetworkList();

    virtual int set(const char *name, const char *value);
    virtual const char *get(const char *name, char *buffer, size_t maxlen);

    ScanResultCollection *createScanResults();

    char *getModulePath() { return mModulePath; }
    char *getModuleName() { return mModuleName; }
    char *getModuleArgs() { return mModuleArgs; }

    Supplicant *getSupplicant() { return mSupplicant; }

protected:
    // Move this crap into a 'driver'
    virtual int powerUp() = 0;
    virtual int powerDown() = 0;
    virtual int loadFirmware();

    virtual bool isFirmwareLoaded() = 0;
    virtual bool isPoweredUp() = 0;

private:
    void sendStatusBroadcast(const char *msg);
    int setScanMode(uint32_t mode);
    int enable();
    int disable();

    // ISupplicantEventHandler methods
    virtual void onAssociatingEvent(SupplicantAssociatingEvent *evt);
    virtual void onAssociatedEvent(SupplicantAssociatedEvent *evt);
    virtual void onConnectedEvent(SupplicantConnectedEvent *evt);
    virtual void onScanResultsEvent(SupplicantScanResultsEvent *evt);
    virtual void onStateChangeEvent(SupplicantStateChangeEvent *evt);
    virtual void onConnectionTimeoutEvent(SupplicantConnectionTimeoutEvent *evt);
    virtual void onDisconnectedEvent(SupplicantDisconnectedEvent *evt);
#if 0
    virtual void onTerminatingEvent(SupplicantEvent *evt);
    virtual void onPasswordChangedEvent(SupplicantEvent *evt);
    virtual void onEapNotificationEvent(SupplicantEvent *evt);
    virtual void onEapStartedEvent(SupplicantEvent *evt);
    virtual void onEapMethodEvent(SupplicantEvent *evt);
    virtual void onEapSuccessEvent(SupplicantEvent *evt);
    virtual void onEapFailureEvent(SupplicantEvent *evt);
    virtual void onLinkSpeedEvent(SupplicantEvent *evt);
    virtual void onDriverStateEvent(SupplicantEvent *evt);
#endif

};

#endif
