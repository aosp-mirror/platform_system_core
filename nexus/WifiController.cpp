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
#include "NetworkManager.h"
#include "ResponseCode.h"
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
#include "WifiStatusPoller.h"

WifiController::WifiController(PropertyManager *mPropMngr,
                               IControllerHandler *handlers,
                               char *modpath, char *modname, char *modargs) :
                Controller("wifi", mPropMngr, handlers) {
    strncpy(mModulePath, modpath, sizeof(mModulePath));
    strncpy(mModuleName, modname, sizeof(mModuleName));
    strncpy(mModuleArgs, modargs, sizeof(mModuleArgs));

    mLatestScanResults = new ScanResultCollection();
    pthread_mutex_init(&mLatestScanResultsLock, NULL);

    pthread_mutex_init(&mLock, NULL);

    mSupplicant = new Supplicant(this, this);
    mActiveScan = false;
    mEnabled = false;
    mScanOnly = false;
    mPacketFilter = false;
    mBluetoothCoexScan = false;
    mBluetoothCoexMode = 0;
    mCurrentlyConnectedNetworkId = -1;
    mStatusPoller = new WifiStatusPoller(this);
    mRssiEventThreshold = 5;
    mLastLinkSpeed = 0;

    mSupplicantState = SupplicantState::UNKNOWN;

    mStaticProperties.propEnabled = new WifiEnabledProperty(this);
    mStaticProperties.propScanOnly = new WifiScanOnlyProperty(this);
    mStaticProperties.propAllowedChannels = new WifiAllowedChannelsProperty(this);

    mStaticProperties.propRssiEventThreshold =
            new IntegerPropertyHelper("RssiEventThreshold", false, &mRssiEventThreshold);

    mDynamicProperties.propSupplicantState = new WifiSupplicantStateProperty(this);
    mDynamicProperties.propActiveScan = new WifiActiveScanProperty(this);
    mDynamicProperties.propInterface = new WifiInterfaceProperty(this);
    mDynamicProperties.propSearching = new WifiSearchingProperty(this);
    mDynamicProperties.propPacketFilter = new WifiPacketFilterProperty(this);
    mDynamicProperties.propBluetoothCoexScan = new WifiBluetoothCoexScanProperty(this);
    mDynamicProperties.propBluetoothCoexMode = new WifiBluetoothCoexModeProperty(this);
    mDynamicProperties.propCurrentNetwork = new WifiCurrentNetworkProperty(this);

    mDynamicProperties.propRssi = new IntegerPropertyHelper("Rssi", true, &mLastRssi);
    mDynamicProperties.propLinkSpeed = new IntegerPropertyHelper("LinkSpeed", true, &mLastLinkSpeed);

    mDynamicProperties.propSuspended = new WifiSuspendedProperty(this);
    mDynamicProperties.propNetCount = new WifiNetCountProperty(this);
    mDynamicProperties.propTriggerScan = new WifiTriggerScanProperty(this);
}

int WifiController::start() {
    mPropMngr->attachProperty("wifi", mStaticProperties.propEnabled);
    mPropMngr->attachProperty("wifi", mStaticProperties.propScanOnly);
    mPropMngr->attachProperty("wifi", mStaticProperties.propAllowedChannels);
    mPropMngr->attachProperty("wifi", mStaticProperties.propRssiEventThreshold);
    return 0;
}

int WifiController::stop() {
    mPropMngr->detachProperty("wifi", mStaticProperties.propEnabled);
    mPropMngr->detachProperty("wifi", mStaticProperties.propScanOnly);
    mPropMngr->detachProperty("wifi", mStaticProperties.propAllowedChannels);
    mPropMngr->detachProperty("wifi", mStaticProperties.propRssiEventThreshold);
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

    LOGW("TODO: Set # of allowed regulatory channels!");

    mPropMngr->attachProperty("wifi", mDynamicProperties.propSupplicantState);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propActiveScan);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propInterface);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propSearching);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propPacketFilter);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propBluetoothCoexScan);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propBluetoothCoexMode);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propCurrentNetwork);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propRssi);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propLinkSpeed);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propSuspended);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propNetCount);
    mPropMngr->attachProperty("wifi", mDynamicProperties.propTriggerScan);

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

bool WifiController::getSuspended() {
    pthread_mutex_lock(&mLock);
    bool r = mSuspended;
    pthread_mutex_unlock(&mLock);
    return r;
}

int WifiController::setSuspend(bool suspend) {

    pthread_mutex_lock(&mLock);
    if (suspend == mSuspended) {
        LOGW("Suspended state already = %d", suspend);
        pthread_mutex_unlock(&mLock);
        return 0;
    }

    if (suspend) {
        mHandlers->onControllerSuspending(this);

        char tmp[80];
        LOGD("Suspending from supplicant state %s",
             SupplicantState::toString(mSupplicantState,
                                       tmp,
                                       sizeof(tmp)));

        if (mSupplicantState != SupplicantState::IDLE) {
            LOGD("Forcing Supplicant disconnect");
            if (mSupplicant->disconnect()) {
                LOGW("Error disconnecting (%s)", strerror(errno));
            }
        }

        LOGD("Stopping Supplicant driver");
        if (mSupplicant->stopDriver()) {
            LOGE("Error stopping driver (%s)", strerror(errno));
            pthread_mutex_unlock(&mLock);
            return -1;
        }
    } else {
        LOGD("Resuming");

        if (mSupplicant->startDriver()) {
            LOGE("Error resuming driver (%s)", strerror(errno));
            pthread_mutex_unlock(&mLock);
            return -1;
        }
        // XXX: set regulatory max channels 
        if (mScanOnly)
            mSupplicant->triggerScan();
        else
            mSupplicant->reconnect();

        mHandlers->onControllerResumed(this);
    }

    mSuspended = suspend;
    pthread_mutex_unlock(&mLock);
    LOGD("Suspend / Resume completed");
    return 0;
}

void WifiController::sendStatusBroadcast(const char *msg) {
    NetworkManager::Instance()->
                    getBroadcaster()->
                    sendBroadcast(ResponseCode::UnsolicitedInformational, msg, false);
}

int WifiController::disable() {

    mPropMngr->detachProperty("wifi", mDynamicProperties.propSupplicantState);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propActiveScan);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propInterface);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propSearching);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propPacketFilter);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propBluetoothCoexScan);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propBluetoothCoexMode);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propCurrentNetwork);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propRssi);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propLinkSpeed);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propSuspended);
    mPropMngr->detachProperty("wifi", mDynamicProperties.propNetCount);

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

int WifiController::triggerScan() {
    pthread_mutex_lock(&mLock);
    if (verifyNotSuspended()) {
        pthread_mutex_unlock(&mLock);
        return -1;
    }

    switch (mSupplicantState) {
        case SupplicantState::DISCONNECTED:
        case SupplicantState::INACTIVE:
        case SupplicantState::SCANNING:
        case SupplicantState::IDLE:
            break;
        default:
            // Switch to scan only mode
            mSupplicant->setApScanMode(2);
            break;
    }

    int rc = mSupplicant->triggerScan();
    pthread_mutex_unlock(&mLock);
    return rc;
}

int WifiController::setActiveScan(bool active) {
    pthread_mutex_lock(&mLock);
    if (mActiveScan == active) {
        pthread_mutex_unlock(&mLock);
        return 0;
    }
    mActiveScan = active;

    int rc = mSupplicant->setScanMode(active);
    pthread_mutex_unlock(&mLock);
    return rc;
}

WifiNetwork *WifiController::createNetwork() {
    pthread_mutex_lock(&mLock);
    WifiNetwork *wn = mSupplicant->createNetwork();
    pthread_mutex_unlock(&mLock);
    return wn;
}

int WifiController::removeNetwork(int networkId) {
    pthread_mutex_lock(&mLock);
    WifiNetwork *wn = mSupplicant->lookupNetwork(networkId);

    if (!wn) {
        pthread_mutex_unlock(&mLock);
        return -1;
    }
    int rc = mSupplicant->removeNetwork(wn);
    pthread_mutex_unlock(&mLock);
    return rc;
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

int WifiController::setPacketFilter(bool enable) {
    int rc;

    pthread_mutex_lock(&mLock);
    if (enable)
        rc = mSupplicant->enablePacketFilter();
    else
        rc = mSupplicant->disablePacketFilter();

    if (!rc)
        mPacketFilter = enable;
    pthread_mutex_unlock(&mLock);
    return rc;
}

int WifiController::setBluetoothCoexistenceScan(bool enable) {
    int rc;

    pthread_mutex_lock(&mLock);

    if (enable)
        rc = mSupplicant->enableBluetoothCoexistenceScan();
    else
        rc = mSupplicant->disableBluetoothCoexistenceScan();

    if (!rc)
        mBluetoothCoexScan = enable;
    pthread_mutex_unlock(&mLock);
    return rc;
}

int WifiController::setScanOnly(bool scanOnly) {
    pthread_mutex_lock(&mLock);
    int rc = mSupplicant->setApScanMode((scanOnly ? 2 : 1));
    if (!rc)
        mScanOnly = scanOnly;
    if (!mSuspended) {
        if (scanOnly)
            mSupplicant->disconnect();
        else
            mSupplicant->reconnect();
    }
    pthread_mutex_unlock(&mLock);
    return rc;
}

int WifiController::setBluetoothCoexistenceMode(int mode) {
    pthread_mutex_lock(&mLock);
    int rc = mSupplicant->setBluetoothCoexistenceMode(mode);
    if (!rc)
        mBluetoothCoexMode = mode;
    pthread_mutex_unlock(&mLock);
    return rc;
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
    
    mCurrentlyConnectedNetworkId = ss->getId();
    if (!(wn = mSupplicant->lookupNetwork(ss->getId()))) {
        LOGW("Error looking up connected network id %d (%s)",
             ss->getId(), strerror(errno));
        return;
    }
  
    delete ss;
    mHandlers->onInterfaceConnected(this);
}

void WifiController::onScanResultsEvent(SupplicantScanResultsEvent *evt) {
    char *reply;

    if (!(reply = (char *) malloc(4096))) {
        LOGE("Out of memory");
        return;
    }

    mNumScanResultsSinceLastStateChange++;
    if (mNumScanResultsSinceLastStateChange >= 3)
        mIsSupplicantSearching = false;

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

    // Switch handling of scan results back to normal mode
    mSupplicant->setApScanMode(1);

    char *tmp;
    asprintf(&tmp, "Scan results ready (%d)", mLatestScanResults->size());
    NetworkManager::Instance()->getBroadcaster()->
                                sendBroadcast(ResponseCode::ScanResultsReady,
                                              tmp, false);
    free(tmp);
    pthread_mutex_unlock(&mLatestScanResultsLock);
    free(reply);
}

void WifiController::onStateChangeEvent(SupplicantStateChangeEvent *evt) {
    char tmp[32];
    char tmp2[32];
    
    if (evt->getState() == mSupplicantState)
        return;

    LOGD("onStateChangeEvent(%s -> %s)", 
         SupplicantState::toString(mSupplicantState, tmp, sizeof(tmp)),
         SupplicantState::toString(evt->getState(), tmp2, sizeof(tmp2)));

    if (evt->getState() != SupplicantState::SCANNING) {
        mIsSupplicantSearching = true;
        mNumScanResultsSinceLastStateChange = 0;
    }

    char *tmp3;
    asprintf(&tmp3,
             "Supplicant state changed from %d (%s) -> %d (%s)",
             mSupplicantState, tmp, evt->getState(), tmp2);

    mSupplicantState = evt->getState();

    if (mSupplicantState == SupplicantState::COMPLETED) {
        mStatusPoller->start();
    } else if (mStatusPoller->isStarted()) {
        mStatusPoller->stop();
    }

    NetworkManager::Instance()->getBroadcaster()->
                                sendBroadcast(ResponseCode::SupplicantStateChange,
                                              tmp3, false);
    free(tmp3);
}

void WifiController::onConnectionTimeoutEvent(SupplicantConnectionTimeoutEvent *evt) {
    LOGD("onConnectionTimeoutEvent(%s)", evt->getBssid());
}

void WifiController::onDisconnectedEvent(SupplicantDisconnectedEvent *evt) {
    mCurrentlyConnectedNetworkId = -1;
    mHandlers->onInterfaceDisconnected(this);
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

void WifiController::onStatusPollInterval() {
    pthread_mutex_lock(&mLock);
    int rssi;
    if (mSupplicant->getRssi(&rssi)) {
        LOGE("Failed to get rssi (%s)", strerror(errno));
        pthread_mutex_unlock(&mLock);
        return;
    }

    if (abs(mLastRssi - rssi) > mRssiEventThreshold) {
        char *tmp3;
        asprintf(&tmp3, "RSSI changed from %d -> %d",
                 mLastRssi, rssi);
        mLastRssi = rssi;
        NetworkManager::Instance()->getBroadcaster()->
                               sendBroadcast(ResponseCode::RssiChange,
                                             tmp3, false);
        free(tmp3);
    }

    int linkspeed = mSupplicant->getLinkSpeed();
    if (linkspeed != mLastLinkSpeed) {
        char *tmp3;
        asprintf(&tmp3, "Link speed changed from %d -> %d",
                 mLastLinkSpeed, linkspeed);
        mLastLinkSpeed = linkspeed;
        NetworkManager::Instance()->getBroadcaster()->
                               sendBroadcast(ResponseCode::LinkSpeedChange,
                                             tmp3, false);
        free(tmp3);
        
    }
    pthread_mutex_unlock(&mLock);
}

int WifiController::verifyNotSuspended() {
    if (mSuspended) {
        errno = ESHUTDOWN;
        return -1;
    }
    return 0;
}

/*
 * Property inner classes
 */

WifiController::WifiIntegerProperty::WifiIntegerProperty(WifiController *c, 
                                                         const char *name,
                                                         bool ro,
                                                         int elements) :
                IntegerProperty(name, ro, elements) {
    mWc = c;
}

WifiController::WifiStringProperty::WifiStringProperty(WifiController *c, 
                                                       const char *name,
                                                       bool ro, int elements) :
                StringProperty(name, ro, elements) {
    mWc = c;
}

WifiController::WifiEnabledProperty::WifiEnabledProperty(WifiController *c) :
                WifiIntegerProperty(c, "Enabled", false, 1) {
}

int WifiController::WifiEnabledProperty::get(int idx, int *buffer) {
    *buffer = mWc->mEnabled;
    return 0;
}
int WifiController::WifiEnabledProperty::set(int idx, int value) {
    int rc = (value ? mWc->enable() : mWc->disable());
    if (!rc)
        mWc->mEnabled = value;
    return rc;
}

WifiController::WifiScanOnlyProperty::WifiScanOnlyProperty(WifiController *c) :
                WifiIntegerProperty(c, "ScanOnly", false, 1) {
}
int WifiController::WifiScanOnlyProperty::get(int idx, int *buffer) {
    *buffer = mWc->mScanOnly;
    return 0;
}
int WifiController::WifiScanOnlyProperty::set(int idx, int value) {
    return mWc->setScanOnly(value == 1);
}

WifiController::WifiAllowedChannelsProperty::WifiAllowedChannelsProperty(WifiController *c) :
                WifiIntegerProperty(c, "AllowedChannels", false, 1) {
}
int WifiController::WifiAllowedChannelsProperty::get(int idx, int *buffer) {
    *buffer = mWc->mNumAllowedChannels;
    return 0;
}
int WifiController::WifiAllowedChannelsProperty::set(int idx, int value) {
    // XXX: IMPL
    errno = ENOSYS;
    return -1;
}

WifiController::WifiSupplicantStateProperty::WifiSupplicantStateProperty(WifiController *c) :
                WifiStringProperty(c, "SupplicantState", true, 1) {
}
int WifiController::WifiSupplicantStateProperty::get(int idx, char *buffer, size_t max) {
    if (!SupplicantState::toString(mWc->mSupplicantState, buffer, max))
        return -1;
    return 0;
}

WifiController::WifiActiveScanProperty::WifiActiveScanProperty(WifiController *c) :
                WifiIntegerProperty(c, "ActiveScan", false, 1) {
}
int WifiController::WifiActiveScanProperty::get(int idx, int *buffer) {
    *buffer = mWc->mActiveScan;
    return 0;
}
int WifiController::WifiActiveScanProperty::set(int idx, int value) {
    return mWc->setActiveScan(value);
}

WifiController::WifiInterfaceProperty::WifiInterfaceProperty(WifiController *c) :
                WifiStringProperty(c, "Interface", true, 1) {
}
int WifiController::WifiInterfaceProperty::get(int idx, char *buffer, size_t max) {
    strncpy(buffer, (mWc->getBoundInterface() ? mWc->getBoundInterface() : "none"), max);
    return 0;
}

WifiController::WifiSearchingProperty::WifiSearchingProperty(WifiController *c) :
                WifiIntegerProperty(c, "Searching", true, 1) {
}
int WifiController::WifiSearchingProperty::get(int idx, int *buffer) {
    *buffer = mWc->mIsSupplicantSearching;
    return 0;
}

WifiController::WifiPacketFilterProperty::WifiPacketFilterProperty(WifiController *c) :
                WifiIntegerProperty(c, "PacketFilter", false, 1) {
}
int WifiController::WifiPacketFilterProperty::get(int idx, int *buffer) {
    *buffer = mWc->mPacketFilter;
    return 0;
}
int WifiController::WifiPacketFilterProperty::set(int idx, int value) {
    return mWc->setPacketFilter(value);
}

WifiController::WifiBluetoothCoexScanProperty::WifiBluetoothCoexScanProperty(WifiController *c) :
                WifiIntegerProperty(c, "BluetoothCoexScan", false, 1) {
}
int WifiController::WifiBluetoothCoexScanProperty::get(int idx, int *buffer) {
    *buffer = mWc->mBluetoothCoexScan;
    return 0;
}
int WifiController::WifiBluetoothCoexScanProperty::set(int idx, int value) {
    return mWc->setBluetoothCoexistenceScan(value == 1);
}

WifiController::WifiBluetoothCoexModeProperty::WifiBluetoothCoexModeProperty(WifiController *c) :
                WifiIntegerProperty(c, "BluetoothCoexMode", false, 1) {
}
int WifiController::WifiBluetoothCoexModeProperty::get(int idx, int *buffer) {
    *buffer = mWc->mBluetoothCoexMode;
    return 0;
}
int WifiController::WifiBluetoothCoexModeProperty::set(int idx, int value) {
    return mWc->setBluetoothCoexistenceMode(value);
}

WifiController::WifiCurrentNetworkProperty::WifiCurrentNetworkProperty(WifiController *c) :
                WifiIntegerProperty(c, "CurrentlyConnectedNetworkId", true, 1) {
}
int WifiController::WifiCurrentNetworkProperty::get(int idx, int *buffer) {
    *buffer = mWc->mCurrentlyConnectedNetworkId;
    return 0;
}

WifiController::WifiSuspendedProperty::WifiSuspendedProperty(WifiController *c) :
                WifiIntegerProperty(c, "Suspended", false, 1) {
}
int WifiController::WifiSuspendedProperty::get(int idx, int *buffer) {
    *buffer = mWc->getSuspended();
    return 0;
}
int WifiController::WifiSuspendedProperty::set(int idx, int value) {
    return mWc->setSuspend(value == 1);
}

WifiController::WifiNetCountProperty::WifiNetCountProperty(WifiController *c) :
                WifiIntegerProperty(c, "NetCount", true, 1) {
}
int WifiController::WifiNetCountProperty::get(int idx, int *buffer) {
    pthread_mutex_lock(&mWc->mLock);
    *buffer = mWc->mSupplicant->getNetworkCount();
    pthread_mutex_unlock(&mWc->mLock);
    return 0;
}

WifiController::WifiTriggerScanProperty::WifiTriggerScanProperty(WifiController *c) :
                WifiIntegerProperty(c, "TriggerScan", false, 1) {
}
int WifiController::WifiTriggerScanProperty::get(int idx, int *buffer) {
    // XXX: Need action type
    *buffer = 0;
    return 0;
}

int WifiController::WifiTriggerScanProperty::set(int idx, int value) {
    return mWc->triggerScan();
}

