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

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define LOG_TAG "WifiController"
#include <cutils/log.h>

#include "Supplicant.h"
#include "WifiController.h"
#include "WifiScanner.h"
#include "NetworkManager.h"
#include "ErrorCode.h"
#include "WifiNetwork.h"
#include "ISupplicantEventHandler.h"
#include "SupplicantState.h"
#include "SupplicantStatus.h"
#include "SupplicantAssociatingEvent.h"
#include "SupplicantAssociatedEvent.h"
#include "SupplicantConnectedEvent.h"
#include "SupplicantScanResultsEvent.h"
#include "SupplicantStateChangeEvent.h"
#include "SupplicantConnectionTimeoutEvent.h"
#include "SupplicantDisconnectedEvent.h"

WifiController::WifiController(PropertyManager *mPropMngr,
                               IControllerHandler *handlers,
                               char *modpath, char *modname, char *modargs) :
                Controller("WIFI", mPropMngr, handlers) {
    strncpy(mModulePath, modpath, sizeof(mModulePath));
    strncpy(mModuleName, modname, sizeof(mModuleName));
    strncpy(mModuleArgs, modargs, sizeof(mModuleArgs));

    mLatestScanResults = new ScanResultCollection();
    pthread_mutex_init(&mLatestScanResultsLock, NULL);

    mSupplicant = new Supplicant(this, this);
    mScanner = new WifiScanner(mSupplicant, 10);
    mCurrentScanMode = 0;

    mEnabled = false;

    mSupplicantState = SupplicantState::UNKNOWN;
}

int WifiController::start() {
    mPropMngr->registerProperty("wifi.enabled", this);
    return 0;
}

int WifiController::stop() {
    mPropMngr->unregisterProperty("wifi.enabled");
    return 0;
}

int WifiController::enable() {

    if (!isPoweredUp()) {
        LOGI("Powering up");
        sendStatusBroadcast("Powering up WiFi hardware");
        if (powerUp()) {
            LOGE("Powerup failed (%s)", strerror(errno));
            return -1;
        }
    }

    if (mModuleName[0] != '\0' && !isKernelModuleLoaded(mModuleName)) {
        LOGI("Loading driver");
        sendStatusBroadcast("Loading WiFi driver");
        if (loadKernelModule(mModulePath, mModuleArgs)) {
            LOGE("Kernel module load failed (%s)", strerror(errno));
            goto out_powerdown;
        }
    }

    if (!isFirmwareLoaded()) {
        LOGI("Loading firmware");
        sendStatusBroadcast("Loading WiFI firmware");
        if (loadFirmware()) {
            LOGE("Firmware load failed (%s)", strerror(errno));
            goto out_powerdown;
        }
    }

    if (!mSupplicant->isStarted()) {
        LOGI("Starting WPA Supplicant");
        sendStatusBroadcast("Starting WPA Supplicant");
        if (mSupplicant->start()) {
            LOGE("Supplicant start failed (%s)", strerror(errno));
            goto out_unloadmodule;
        }
    }

    if (Controller::bindInterface(mSupplicant->getInterfaceName())) {
        LOGE("Error binding interface (%s)", strerror(errno));
        goto out_unloadmodule;
    }

    if (mSupplicant->refreshNetworkList())
        LOGW("Error getting list of networks (%s)", strerror(errno));

    mPropMngr->registerProperty("wifi.supplicant.state", this);
    mPropMngr->registerProperty("wifi.scanmode", this);
    mPropMngr->registerProperty("wifi.interface", this);

    LOGI("Enabled successfully");
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

void WifiController::sendStatusBroadcast(const char *msg) {
    NetworkManager::Instance()->
                    getBroadcaster()->
                    sendBroadcast(ErrorCode::UnsolicitedInformational, msg, false);
}

int WifiController::disable() {

    mPropMngr->unregisterProperty("wifi.scanmode");
    mPropMngr->unregisterProperty("wifi.supplicant.state");
    mPropMngr->unregisterProperty("wifi.scanmode");

    if (mSupplicant->isStarted()) {
        sendStatusBroadcast("Stopping WPA Supplicant");
        if (mSupplicant->stop()) {
            LOGE("Supplicant stop failed (%s)", strerror(errno));
            return -1;
        }
    } else
        LOGW("disable(): Supplicant not running?");

    if (mModuleName[0] != '\0' && isKernelModuleLoaded(mModuleName)) {
        sendStatusBroadcast("Unloading WiFi driver");
        if (unloadKernelModule(mModuleName)) {
            LOGE("Unable to unload module (%s)", strerror(errno));
            return -1;
        }
    }

    if (isPoweredUp()) {
        sendStatusBroadcast("Powering down WiFi hardware");
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
            mScanner->stop();
    } else if (mode & SCAN_REPEAT_MASK)
        rc = mScanner->start(mode & SCAN_ACTIVE_MASK);
    else
        rc = mSupplicant->triggerScan(mode & SCAN_ACTIVE_MASK);

    mCurrentScanMode = mode;
    return rc;
}

WifiNetwork *WifiController::createNetwork() {
    WifiNetwork *wn = mSupplicant->createNetwork();
    return wn;
}

int WifiController::removeNetwork(int networkId) {
    WifiNetwork *wn = mSupplicant->lookupNetwork(networkId);

    if (!wn)
        return -1;
    return mSupplicant->removeNetwork(wn);
}

ScanResultCollection *WifiController::createScanResults() {
    ScanResultCollection *d = new ScanResultCollection();
    ScanResultCollection::iterator i;

    pthread_mutex_lock(&mLatestScanResultsLock);
    for (i = mLatestScanResults->begin(); i != mLatestScanResults->end(); ++i)
        d->push_back((*i)->clone());

    pthread_mutex_unlock(&mLatestScanResultsLock);
    return d;
}

WifiNetworkCollection *WifiController::createNetworkList() {
    return mSupplicant->createNetworkList();
}

int WifiController::set(const char *name, const char *value) {
    int rc;

    if (!strcmp(name, "wifi.enabled")) {
        int en = atoi(value);

        if (en == mEnabled)
            return 0;
        rc = (en ? enable() : disable());
        if (!rc)
            mEnabled = en;
    } else if (!strcmp(name, "wifi.interface")) {
        errno = EROFS;
        return -1;
    } else if (!strcmp(name, "wifi.scanmode"))
        return setScanMode((uint32_t) strtoul(value, NULL, 0));
    else if (!strcmp(name, "wifi.supplicant.state")) {
        errno = EROFS;
        return -1;
    } else
        return Controller::set(name, value);
    return rc;
}

const char *WifiController::get(const char *name, char *buffer, size_t maxsize) {

    if (!strcmp(name, "wifi.enabled"))
        snprintf(buffer, maxsize, "%d", mEnabled);
    else if (!strcmp(name, "wifi.interface")) {
        snprintf(buffer, maxsize, "%s",
                 (getBoundInterface() ? getBoundInterface() : "none"));
    } else if (!strcmp(name, "wifi.scanmode"))
        snprintf(buffer, maxsize, "0x%.8x", mCurrentScanMode);
    else if (!strcmp(name, "wifi.supplicant.state"))
        return SupplicantState::toString(mSupplicantState, buffer, maxsize);
    else
        return Controller::get(name, buffer, maxsize);

    return buffer;
}

void WifiController::onAssociatingEvent(SupplicantAssociatingEvent *evt) {
    LOGD("onAssociatingEvent(%s, %s, %d)",
         (evt->getBssid() ? evt->getBssid() : "n/a"),
         (evt->getSsid() ? evt->getSsid() : "n/a"),
         evt->getFreq());
}

void WifiController::onAssociatedEvent(SupplicantAssociatedEvent *evt) {
    LOGD("onAssociatedEvent(%s)", evt->getBssid());
}

void WifiController::onConnectedEvent(SupplicantConnectedEvent *evt) {
    LOGD("onConnectedEvent(%s, %d)", evt->getBssid(), evt->getReassociated());
    SupplicantStatus *ss = mSupplicant->getStatus();
    WifiNetwork *wn;

    if (ss->getWpaState() != SupplicantState::COMPLETED) {
        char tmp[32];

        LOGW("onConnected() with SupplicantState = %s!",
             SupplicantState::toString(ss->getWpaState(), tmp,
             sizeof(tmp)));
        return;
    }

    if (ss->getId() == -1) {
        LOGW("onConnected() with id = -1!");
        return;
    }
    
    if (!(wn = mSupplicant->lookupNetwork(ss->getId()))) {
        LOGW("Error looking up connected network id %d (%s)",
             ss->getId(), strerror(errno));
        return;
    }
  
    delete ss;
    mHandlers->onInterfaceConnected(this, wn->getIfaceCfg());
}

void WifiController::onScanResultsEvent(SupplicantScanResultsEvent *evt) {
    char *reply;

    if (!(reply = (char *) malloc(4096))) {
        LOGE("Out of memory");
        return;
    }

    size_t len = 4096;

    if (mSupplicant->sendCommand("SCAN_RESULTS", reply, &len)) {
        LOGW("onScanResultsEvent: Error getting scan results (%s)",
             strerror(errno));
        free(reply);
        return;
    }

    pthread_mutex_lock(&mLatestScanResultsLock);
    if (!mLatestScanResults->empty()) {
        ScanResultCollection::iterator i;

        for (i = mLatestScanResults->begin();
             i !=mLatestScanResults->end(); ++i) {
            delete *i;
        }
        mLatestScanResults->clear();
    }

    char *linep;
    char *linep_next = NULL;

    if (!strtok_r(reply, "\n", &linep_next)) {
        free(reply);
        pthread_mutex_unlock(&mLatestScanResultsLock);
        return;
    }

    while((linep = strtok_r(NULL, "\n", &linep_next)))
        mLatestScanResults->push_back(new ScanResult(linep));

    char *tmp;
    asprintf(&tmp, "Scan results ready (%d)", mLatestScanResults->size());
    NetworkManager::Instance()->getBroadcaster()->
                                sendBroadcast(ErrorCode::UnsolicitedInformational, tmp, false);
    free(tmp);
    pthread_mutex_unlock(&mLatestScanResultsLock);
    free(reply);
}

void WifiController::onStateChangeEvent(SupplicantStateChangeEvent *evt) {
    char tmp[32];
    char tmp2[32];
    
    LOGD("onStateChangeEvent(%s -> %s)", 
         SupplicantState::toString(mSupplicantState, tmp, sizeof(tmp)),
         SupplicantState::toString(evt->getState(), tmp2, sizeof(tmp2)));

    mSupplicantState = evt->getState();
}

void WifiController::onConnectionTimeoutEvent(SupplicantConnectionTimeoutEvent *evt) {
    LOGD("onConnectionTimeoutEvent(%s)", evt->getBssid());
}

void WifiController::onDisconnectedEvent(SupplicantDisconnectedEvent *evt) {
    mHandlers->onInterfaceDisconnected(this, getBoundInterface());
}

#if 0
void WifiController::onTerminatingEvent(SupplicantEvent *evt) {
    LOGD("onTerminatingEvent(%s)", evt->getEvent());
}

void WifiController::onPasswordChangedEvent(SupplicantEvent *evt) {
    LOGD("onPasswordChangedEvent(%s)", evt->getEvent());
}

void WifiController::onEapNotificationEvent(SupplicantEvent *evt) {
    LOGD("onEapNotificationEvent(%s)", evt->getEvent());
}

void WifiController::onEapStartedEvent(SupplicantEvent *evt) {
    LOGD("onEapStartedEvent(%s)", evt->getEvent());
}

void WifiController::onEapMethodEvent(SupplicantEvent *evt) {
    LOGD("onEapMethodEvent(%s)", evt->getEvent());
}

void WifiController::onEapSuccessEvent(SupplicantEvent *evt) {
    LOGD("onEapSuccessEvent(%s)", evt->getEvent());
}

void WifiController::onEapFailureEvent(SupplicantEvent *evt) {
    LOGD("onEapFailureEvent(%s)", evt->getEvent());
}

void WifiController::onLinkSpeedEvent(SupplicantEvent *evt) {
    LOGD("onLinkSpeedEvent(%s)", evt->getEvent());
}

void WifiController::onDriverStateEvent(SupplicantEvent *evt) {
    LOGD("onDriverStateEvent(%s)", evt->getEvent());
}
#endif
