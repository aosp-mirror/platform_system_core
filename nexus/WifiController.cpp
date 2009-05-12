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
#include <string.h>
#include <errno.h>

#define LOG_TAG "WifiController"
#include <cutils/log.h>

#include "Supplicant.h"
#include "WifiController.h"
#include "WifiScanner.h"
#include "NetworkManager.h"
#include "ErrorCode.h";

WifiController::WifiController(char *modpath, char *modname, char *modargs) :
                Controller("WIFI") {
    strncpy(mModulePath, modpath, sizeof(mModulePath));
    strncpy(mModuleName, modname, sizeof(mModuleName));
    strncpy(mModuleArgs, modargs, sizeof(mModuleArgs));

    mSupplicant = new Supplicant();
    mScanner = new WifiScanner(mSupplicant, 10);
    mCurrentScanMode = 0;
}

int WifiController::start() {
    return 0;
}

int WifiController::stop() {
    errno = ENOSYS;
    return -1;
}

int WifiController::enable() {
    if (!isPoweredUp()) {
        sendStatusBroadcast("POWERING_UP");
        if (powerUp()) {
            LOGE("Powerup failed (%s)", strerror(errno));
            return -1;
        }
    }

    if (mModuleName[0] != '\0' && !isKernelModuleLoaded(mModuleName)) {
        sendStatusBroadcast("LOADING_DRIVER");
        if (loadKernelModule(mModulePath, mModuleArgs)) {
            LOGE("Kernel module load failed (%s)", strerror(errno));
            goto out_powerdown;
        }
    }

    if (!isFirmwareLoaded()) {
        sendStatusBroadcast("LOADING_FIRMWARE");
        if (loadFirmware()) {
            LOGE("Firmware load failed (%s)", strerror(errno));
            goto out_powerdown;
        }
    }

    if (!mSupplicant->isStarted()) {
        sendStatusBroadcast("STARTING_SUPPLICANT");
        if (mSupplicant->start()) {
            LOGE("Supplicant start failed (%s)", strerror(errno));
            goto out_unloadmodule;
        }
    }

    return 0;

out_unloadmodule:
    if (mModuleName[0] != '\0' && !isKernelModuleLoaded(mModuleName)) {
        if (unloadKernelModule(mModuleName)) {
            LOGE("Unable to unload module after failure!");
        }
    }

out_powerdown:
    if (powerDown()) {
        LOGE("Unable to powerdown after failure!");
    }
    return -1;
}

void WifiController::sendStatusBroadcast(char *msg) {
    NetworkManager::Instance()->
                    getBroadcaster()->
                    sendBroadcast(ErrorCode::UnsolicitedInformational, msg, false);
}

int WifiController::disable() {

    if (mSupplicant->isStarted()) {
        sendStatusBroadcast("STOPPING_SUPPLICANT");
        if (mSupplicant->stop()) {
            LOGE("Supplicant stop failed (%s)", strerror(errno));
            return -1;
        }
    } else 
        LOGW("disable(): Supplicant not running?");

    if (mModuleName[0] != '\0' && isKernelModuleLoaded(mModuleName)) {
        sendStatusBroadcast("UNLOADING_DRIVER");
        if (unloadKernelModule(mModuleName)) {
            LOGE("Unable to unload module (%s)", strerror(errno));
            return -1;
        }
    }

    if (isPoweredUp()) {
        sendStatusBroadcast("POWERING_DOWN");
        if (powerDown()) {
            LOGE("Powerdown failed (%s)", strerror(errno));
            return -1;
        }
    }
    return 0;
}

int WifiController::loadFirmware() {
    return 0;
}

int WifiController::setScanMode(uint32_t mode) {
    int rc = 0;

    if (mCurrentScanMode == mode)
        return 0;

    if (!(mode & SCAN_ENABLE_MASK)) {
        if (mCurrentScanMode & SCAN_REPEAT_MASK)
            mScanner->stopPeriodicScan();
    } else if (mode & SCAN_REPEAT_MASK)
        rc = mScanner->startPeriodicScan(mode & SCAN_ACTIVE_MASK);
    else
        rc = mSupplicant->triggerScan(mode & SCAN_ACTIVE_MASK);
    
    return rc;
}

ScanResultCollection *WifiController::createScanResults() {
    return mSupplicant->createLatestScanResults();
}
