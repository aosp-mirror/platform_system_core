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

class NetInterface;
class Supplicant;
class WifiScanner;

#include "ScanResult.h"
#include "WifiNetwork.h"

class WifiController : public Controller {
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

public:
    WifiController(char *modpath, char *modname, char *modargs);
    virtual ~WifiController() {}

    int start();
    int stop();

    int enable();
    int disable();

    int addNetwork();
    int removeNetwork(int networkId);
    WifiNetworkCollection *createNetworkList();

    int getScanMode() { return mCurrentScanMode; }
    int setScanMode(uint32_t mode);
    ScanResultCollection *createScanResults();

    char *getModulePath() { return mModulePath; }
    char *getModuleName() { return mModuleName; }
    char *getModuleArgs() { return mModuleArgs; }

    Supplicant *getSupplicant() { return mSupplicant; }

protected:
    virtual int powerUp() = 0;
    virtual int powerDown() = 0;
    virtual int loadFirmware();

    virtual bool isFirmwareLoaded() = 0;
    virtual bool isPoweredUp() = 0;

    void sendStatusBroadcast(char *msg);
};

#endif
