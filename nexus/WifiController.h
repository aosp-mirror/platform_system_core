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
#include "IWifiStatusPollerHandler.h"

class NetInterface;
class Supplicant;
class SupplicantAssociatingEvent;
class SupplicantAssociatedEvent;
class SupplicantConnectedEvent;
class SupplicantScanResultsEvent;
class SupplicantStateChangeEvent;
class SupplicantDisconnectedEvent;
class WifiStatusPoller;

class WifiController : public Controller,
                       public ISupplicantEventHandler,
                       public IWifiStatusPollerHandler {

    class WifiIntegerProperty : public IntegerProperty {
    protected:
        WifiController *mWc;
    public:
        WifiIntegerProperty(WifiController *c, const char *name, bool ro, 
                            int elements);
        virtual ~WifiIntegerProperty() {}
        virtual int set(int idx, int value) = 0;
        virtual int get(int idx, int *buffer) = 0;
    };
    friend class WifiController::WifiIntegerProperty;

    class WifiStringProperty : public StringProperty {
    protected:
        WifiController *mWc;
    public:
        WifiStringProperty(WifiController *c, const char *name, bool ro, 
                            int elements);
        virtual ~WifiStringProperty() {}
        virtual int set(int idx, const char *value) = 0;
        virtual int get(int idx, char *buffer, size_t max) = 0;
    };
    friend class WifiController::WifiStringProperty;

    class WifiEnabledProperty : public WifiIntegerProperty {
    public:
        WifiEnabledProperty(WifiController *c);
        virtual ~WifiEnabledProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiScanOnlyProperty : public WifiIntegerProperty {
    public:
        WifiScanOnlyProperty(WifiController *c);
        virtual ~WifiScanOnlyProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiAllowedChannelsProperty : public WifiIntegerProperty {
    public:
        WifiAllowedChannelsProperty(WifiController *c);
        virtual ~WifiAllowedChannelsProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiActiveScanProperty : public WifiIntegerProperty {
    public:
        WifiActiveScanProperty(WifiController *c);
        virtual ~WifiActiveScanProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiSearchingProperty : public WifiIntegerProperty {
    public:
        WifiSearchingProperty(WifiController *c);
        virtual ~WifiSearchingProperty() {}
        int set(int idx, int value) { return -1; }
        int get(int idx, int *buffer);
    };

    class WifiPacketFilterProperty : public WifiIntegerProperty {
    public:
        WifiPacketFilterProperty(WifiController *c);
        virtual ~WifiPacketFilterProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiBluetoothCoexScanProperty : public WifiIntegerProperty {
    public:
        WifiBluetoothCoexScanProperty(WifiController *c);
        virtual ~WifiBluetoothCoexScanProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiBluetoothCoexModeProperty : public WifiIntegerProperty {
    public:
        WifiBluetoothCoexModeProperty(WifiController *c);
        virtual ~WifiBluetoothCoexModeProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiCurrentNetworkProperty : public WifiIntegerProperty {
    public:
        WifiCurrentNetworkProperty(WifiController *c);
        virtual ~WifiCurrentNetworkProperty() {}
        int set(int idx, int value) { return -1; }
        int get(int idx, int *buffer);
    };

    class WifiSuspendedProperty : public WifiIntegerProperty {
    public:
        WifiSuspendedProperty(WifiController *c);
        virtual ~WifiSuspendedProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiNetCountProperty : public WifiIntegerProperty {
    public:
        WifiNetCountProperty(WifiController *c);
        virtual ~WifiNetCountProperty() {}
        int set(int idx, int value) { return -1; }
        int get(int idx, int *buffer);
    };

    class WifiTriggerScanProperty : public WifiIntegerProperty {
    public:
        WifiTriggerScanProperty(WifiController *c);
        virtual ~WifiTriggerScanProperty() {}
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiSupplicantStateProperty : public WifiStringProperty {
    public:
        WifiSupplicantStateProperty(WifiController *c);
        virtual ~WifiSupplicantStateProperty() {}
        int set(int idx, const char *value) { return -1; }
        int get(int idx, char *buffer, size_t max);
    };

    class WifiInterfaceProperty : public WifiStringProperty {
    public:
        WifiInterfaceProperty(WifiController *c);
        virtual ~WifiInterfaceProperty() {}
        int set(int idx, const char *value) { return -1; }
        int get(int idx, char *buffer, size_t max);
    };

    Supplicant *mSupplicant;
    char        mModulePath[255];
    char        mModuleName[64];
    char        mModuleArgs[255];

    int         mSupplicantState;
    bool        mActiveScan;
    bool        mScanOnly;
    bool        mPacketFilter;
    bool        mBluetoothCoexScan;
    int         mBluetoothCoexMode;
    int         mCurrentlyConnectedNetworkId;
    bool        mSuspended;
    int         mLastRssi;
    int         mRssiEventThreshold;
    int         mLastLinkSpeed;
    int         mNumAllowedChannels;

    ScanResultCollection *mLatestScanResults;
    pthread_mutex_t      mLatestScanResultsLock;
    pthread_mutex_t      mLock;
    WifiStatusPoller     *mStatusPoller;

    struct {
        WifiEnabledProperty         *propEnabled;
        WifiScanOnlyProperty        *propScanOnly;
        WifiAllowedChannelsProperty *propAllowedChannels;
        IntegerPropertyHelper       *propRssiEventThreshold;
    } mStaticProperties;

    struct {
        WifiActiveScanProperty        *propActiveScan;
        WifiSearchingProperty         *propSearching;
        WifiPacketFilterProperty      *propPacketFilter;
        WifiBluetoothCoexScanProperty *propBluetoothCoexScan;
        WifiBluetoothCoexModeProperty *propBluetoothCoexMode;
        WifiCurrentNetworkProperty    *propCurrentNetwork;
        IntegerPropertyHelper         *propRssi;
        IntegerPropertyHelper         *propLinkSpeed;
        WifiSuspendedProperty         *propSuspended;
        WifiNetCountProperty          *propNetCount;
        WifiSupplicantStateProperty   *propSupplicantState;
        WifiInterfaceProperty         *propInterface;
        WifiTriggerScanProperty       *propTriggerScan;
    } mDynamicProperties;

    // True if supplicant is currently searching for a network
    bool mIsSupplicantSearching;
    int  mNumScanResultsSinceLastStateChange;

    bool        mEnabled;

public:
    WifiController(PropertyManager *propmngr, IControllerHandler *handlers, char *modpath, char *modname, char *modargs);
    virtual ~WifiController() {}

    int start();
    int stop();

    WifiNetwork *createNetwork();
    int removeNetwork(int networkId);
    WifiNetworkCollection *createNetworkList();

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
    int setActiveScan(bool active);
    int triggerScan();
    int enable();
    int disable();
    int setSuspend(bool suspend);
    bool getSuspended();
    int setBluetoothCoexistenceScan(bool enable);
    int setBluetoothCoexistenceMode(int mode);
    int setPacketFilter(bool enable);
    int setScanOnly(bool scanOnly);

    // ISupplicantEventHandler methods
    void onAssociatingEvent(SupplicantAssociatingEvent *evt);
    void onAssociatedEvent(SupplicantAssociatedEvent *evt);
    void onConnectedEvent(SupplicantConnectedEvent *evt);
    void onScanResultsEvent(SupplicantScanResultsEvent *evt);
    void onStateChangeEvent(SupplicantStateChangeEvent *evt);
    void onConnectionTimeoutEvent(SupplicantConnectionTimeoutEvent *evt);
    void onDisconnectedEvent(SupplicantDisconnectedEvent *evt);
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

    void onStatusPollInterval();

    int verifyNotSuspended();
};

#endif
