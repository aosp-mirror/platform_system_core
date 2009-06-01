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
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#define LOG_TAG "Supplicant"
#include <cutils/log.h>
#include <cutils/properties.h>

#include "private/android_filesystem_config.h"

#include <sysutils/ServiceManager.h>

#include "Supplicant.h"
#include "SupplicantListener.h"
#include "SupplicantState.h"
#include "SupplicantEvent.h"
#include "ScanResult.h"
#include "PropertyManager.h"
#include "NetworkManager.h"
#include "ErrorCode.h"
#include "WifiController.h"

#include "libwpa_client/wpa_ctrl.h"

#define IFACE_DIR        "/data/system/wpa_supplicant"
#define DRIVER_PROP_NAME "wlan.driver.status"
#define SUPPLICANT_SERVICE_NAME  "wpa_supplicant"
#define SUPP_CONFIG_TEMPLATE "/system/etc/wifi/wpa_supplicant.conf"
#define SUPP_CONFIG_FILE "/data/misc/wifi/wpa_supplicant.conf"

Supplicant::Supplicant(WifiController *wc, PropertyManager *propmngr) {
    mController = wc;
    mPropMngr = propmngr;
    mInterfaceName = NULL;
    mCtrl = NULL;
    mMonitor = NULL;
    mListener = NULL;
   
    mState = SupplicantState::UNKNOWN;

    mServiceManager = new ServiceManager();

    mLatestScanResults = new ScanResultCollection();
    pthread_mutex_init(&mLatestScanResultsLock, NULL);

    mNetworks = new WifiNetworkCollection();
    pthread_mutex_init(&mNetworksLock, NULL);
}

Supplicant::~Supplicant() {
    delete mServiceManager;
    if (mInterfaceName)
        free(mInterfaceName);
}

int Supplicant::start() {

    if (setupConfig()) {
        LOGW("Unable to setup supplicant.conf");
    }

    if (mServiceManager->start(SUPPLICANT_SERVICE_NAME)) {
        LOGE("Error starting supplicant (%s)", strerror(errno));
        return -1;
    }

    wpa_ctrl_cleanup();
    if (connectToSupplicant()) {
        LOGE("Error connecting to supplicant (%s)\n", strerror(errno));
        return -1;
    }
    
    if (retrieveInterfaceName()) {
        LOGE("Error retrieving interface name (%s)\n", strerror(errno));
        return -1;
    }

    mPropMngr->registerProperty("wifi.supplicant.state", this);
    return 0;
}

int Supplicant::stop() {

    mPropMngr->unregisterProperty("wifi.supplicant.state");

    if (mListener->stopListener()) {
        LOGW("Unable to stop supplicant listener (%s)", strerror(errno));
        return -1;
    }

    if (mServiceManager->stop(SUPPLICANT_SERVICE_NAME)) {
        LOGW("Error stopping supplicant (%s)", strerror(errno));
    }

    if (mCtrl) {
        wpa_ctrl_close(mCtrl);
        mCtrl = NULL;
    }
    if (mMonitor) {
        wpa_ctrl_close(mMonitor);
        mMonitor = NULL;
    }

    return 0;
}

bool Supplicant::isStarted() {
    return mServiceManager->isRunning(SUPPLICANT_SERVICE_NAME);
}

int Supplicant::refreshNetworkList() {
    char *reply;
    size_t len = 4096;

    if (!(reply = (char *) malloc(len))) {
        errno = ENOMEM;
        return -1;
    }

    if (sendCommand("LIST_NETWORKS", reply, &len)) {
        free(reply);
        return -1;
    }

    char *linep;
    char *linep_next = NULL;

    if (!strtok_r(reply, "\n", &linep_next)) {
        LOGW("Malformatted network list\n");
    } else {
        pthread_mutex_lock(&mNetworksLock);
        if (!mNetworks->empty()) {
            WifiNetworkCollection::iterator i;

            for (i = mNetworks->begin(); i !=mNetworks->end(); ++i)
                delete *i;
            mNetworks->clear();
        }

        while((linep = strtok_r(NULL, "\n", &linep_next))) {
            WifiNetwork *wn = new WifiNetwork(mController, this, linep);
            mNetworks->push_back(wn);
            if (wn->refresh())
                LOGW("Unable to refresh network id %d", wn->getNetworkId());
        }

        LOGD("Loaded %d networks\n", mNetworks->size());
        pthread_mutex_unlock(&mNetworksLock);
    }

    free(reply);
    return 0;
}

int Supplicant::connectToSupplicant() {
    if (!isStarted())
        LOGW("Supplicant service not running");

    mCtrl = wpa_ctrl_open("tiwlan0"); // XXX:
    if (mCtrl == NULL) {
        LOGE("Unable to open connection to supplicant on \"%s\": %s",
             "tiwlan0", strerror(errno));
        return -1;
    }
    mMonitor = wpa_ctrl_open("tiwlan0");
    if (mMonitor == NULL) {
        wpa_ctrl_close(mCtrl);
        mCtrl = NULL;
        return -1;
    }
    if (wpa_ctrl_attach(mMonitor) != 0) {
        wpa_ctrl_close(mMonitor);
        wpa_ctrl_close(mCtrl);
        mCtrl = mMonitor = NULL;
        return -1;
    }

    mListener = new SupplicantListener(this, mMonitor);

    if (mListener->startListener()) {
        LOGE("Error - unable to start supplicant listener");
        stop();
        return -1;
    }
    return 0;
}

int Supplicant::sendCommand(const char *cmd, char *reply, size_t *reply_len)
{
    if (!mCtrl) {
        errno = ENOTCONN;
        return -1;
    }

//    LOGD("sendCommand(): -> '%s'", cmd);

    int rc;
    memset(reply, 0, *reply_len);
    if ((rc = wpa_ctrl_request(mCtrl, cmd, strlen(cmd), reply, reply_len, NULL)) == -2)  {
        errno = ETIMEDOUT;
        return -1;
    } else if (rc < 0 || !strncmp(reply, "FAIL", 4)) {
        strcpy(reply, "FAIL");
        errno = EIO;
        return -1;
    }

//   LOGD("sendCommand(): <- '%s'", reply);
    return 0;
}

int Supplicant::triggerScan(bool active) {
    char reply[255];
    size_t len = sizeof(reply);

    if (sendCommand((active ? "DRIVER SCAN-ACTIVE" : "DRIVER SCAN-PASSIVE"),
                     reply, &len)) {
        LOGW("triggerScan(%d): Error setting scan mode (%s)", active,
             strerror(errno));
        return -1;
    }
    len = sizeof(reply);

    if (sendCommand("SCAN", reply, &len)) {
        LOGW("triggerScan(%d): Error initiating scan", active);
        return -1;
    }
    return 0;
}

int Supplicant::set(const char *name, const char *value) {
    const char *n = name + strlen("wifi.supplicant.");

    errno = -EROFS;
    return -1;
}

const char *Supplicant::get(const char *name, char *buffer, size_t max) {
    const char *n = name + strlen("wifi.supplicant.");

    if (!strcasecmp(n, "state"))
        return SupplicantState::toString(mState, buffer, max);
    errno = ENOENT;
    return NULL;
}

int Supplicant::onConnectedEvent(SupplicantEvent *evt) {
    LOGD("onConnectedEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onDisconnectedEvent(SupplicantEvent *evt) {
    LOGD("onDisconnectedEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onTerminatingEvent(SupplicantEvent *evt) {
    LOGD("onTerminatingEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onPasswordChangedEvent(SupplicantEvent *evt) {
    LOGD("onPasswordChangedEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onEapNotificationEvent(SupplicantEvent *evt) {
    LOGD("onEapNotificationEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onEapStartedEvent(SupplicantEvent *evt) {
    LOGD("onEapStartedEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onEapMethodEvent(SupplicantEvent *evt) {
    LOGD("onEapMethodEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onEapSuccessEvent(SupplicantEvent *evt) {
    LOGD("onEapSuccessEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onEapFailureEvent(SupplicantEvent *evt) {
    LOGD("onEapFailureEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onScanResultsEvent(SupplicantEvent *evt) {
    if (!strcmp(evt->getEvent(), "Ready")) {
        char *reply;

        if (!(reply = (char *) malloc(4096))) {
            errno = ENOMEM;
            return -1;
        }

        size_t len = 4096;

        if (sendCommand("SCAN_RESULTS", reply, &len)) {
            LOGW("onScanResultsEvent(%s): Error getting scan results (%s)",
                  evt->getEvent(), strerror(errno));
            free(reply);
            return -1;
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
            return 0;
        }

        while((linep = strtok_r(NULL, "\n", &linep_next)))
            mLatestScanResults->push_back(new ScanResult(linep));

        char tmp[128];
        sprintf(tmp, "Scan results ready (%d)", mLatestScanResults->size());
        NetworkManager::Instance()->getBroadcaster()->
                                    sendBroadcast(ErrorCode::UnsolicitedInformational, tmp, false);
        pthread_mutex_unlock(&mLatestScanResultsLock);
        free(reply);
    } else {
        LOGW("Unknown SCAN_RESULTS event (%s)", evt->getEvent());
    }
    return 0;
}

int Supplicant::onStateChangeEvent(SupplicantEvent *evt) {
    char *bword, *last;
    char *tmp = strdup(evt->getEvent());

    if (!(bword = strtok_r(tmp, " ", &last))) {
        LOGE("Malformatted state update (%s)", evt->getEvent());
        free(tmp);
        return 0;
    }

    if (!(bword = strtok_r(NULL, " ", &last))) {
        LOGE("Malformatted state update (%s)", evt->getEvent());
        free(tmp);
        return 0;
    }

    mState = atoi(&bword[strlen("state=")]);
    LOGD("State changed to %d", mState);
    free(tmp);
    return 0;
}

int Supplicant::onLinkSpeedEvent(SupplicantEvent *evt) {
    LOGD("onLinkSpeedEvent(%s)", evt->getEvent());
    return 0;
}

int Supplicant::onDriverStateEvent(SupplicantEvent *evt) {
    LOGD("onDriverStateEvent(%s)", evt->getEvent());
    return 0;
}

// XXX: Use a cursor + smartptr instead
ScanResultCollection *Supplicant::createLatestScanResults() {
    ScanResultCollection *d = new ScanResultCollection();
    ScanResultCollection::iterator i;

    pthread_mutex_lock(&mLatestScanResultsLock);
    for (i = mLatestScanResults->begin(); i != mLatestScanResults->end(); ++i)
        d->push_back((*i)->clone());

    pthread_mutex_unlock(&mLatestScanResultsLock);
    return d;
}

WifiNetwork *Supplicant::createNetwork() {
    char reply[255];
    size_t len = sizeof(reply) -1;

    if (sendCommand("ADD_NETWORK", reply, &len))
        return NULL;

    if (reply[strlen(reply) -1] == '\n')
        reply[strlen(reply) -1] = '\0';

    WifiNetwork *wn = new WifiNetwork(mController, this, atoi(reply));
    pthread_mutex_lock(&mNetworksLock);
    mNetworks->push_back(wn);
    pthread_mutex_unlock(&mNetworksLock);
    return wn;
}

int Supplicant::removeNetwork(WifiNetwork *wn) {
    char req[64];

    sprintf(req, "REMOVE_NETWORK %d", wn->getNetworkId());
    char reply[32];
    size_t len = sizeof(reply) -1;

    if (sendCommand(req, reply, &len))
        return -1;

    pthread_mutex_lock(&mNetworksLock);
    WifiNetworkCollection::iterator it;
    for (it = mNetworks->begin(); it != mNetworks->end(); ++it) {
        if ((*it) == wn) {
            mNetworks->erase(it);
            break;
        }
    }
    pthread_mutex_unlock(&mNetworksLock);
    return 0;
}

WifiNetwork *Supplicant::lookupNetwork(int networkId) {
    pthread_mutex_lock(&mNetworksLock);
    WifiNetworkCollection::iterator it;
    for (it = mNetworks->begin(); it != mNetworks->end(); ++it) {
        if ((*it)->getNetworkId() == networkId) {
            pthread_mutex_unlock(&mNetworksLock);
            return *it;
        }
    }
    pthread_mutex_unlock(&mNetworksLock);
    errno = ENOENT;
    return NULL;
}

WifiNetworkCollection *Supplicant::createNetworkList() {
    WifiNetworkCollection *d = new WifiNetworkCollection();
    WifiNetworkCollection::iterator i;

    pthread_mutex_lock(&mNetworksLock);
    for (i = mNetworks->begin(); i != mNetworks->end(); ++i)
        d->push_back((*i)->clone());

    pthread_mutex_unlock(&mNetworksLock);
    return d;
}

int Supplicant::setupConfig() {
    char buf[2048];
    int srcfd, destfd;
    int nread;

    if (access(SUPP_CONFIG_FILE, R_OK|W_OK) == 0) {
        return 0;
    } else if (errno != ENOENT) {
        LOGE("Cannot access \"%s\": %s", SUPP_CONFIG_FILE, strerror(errno));
        return -1;
    }

    srcfd = open(SUPP_CONFIG_TEMPLATE, O_RDONLY);
    if (srcfd < 0) {
        LOGE("Cannot open \"%s\": %s", SUPP_CONFIG_TEMPLATE, strerror(errno));
        return -1;
    }

    destfd = open(SUPP_CONFIG_FILE, O_CREAT|O_WRONLY, 0660);
    if (destfd < 0) {
        close(srcfd);
        LOGE("Cannot create \"%s\": %s", SUPP_CONFIG_FILE, strerror(errno));
        return -1;
    }

    while ((nread = read(srcfd, buf, sizeof(buf))) != 0) {
        if (nread < 0) {
            LOGE("Error reading \"%s\": %s", SUPP_CONFIG_TEMPLATE, strerror(errno));
            close(srcfd);
            close(destfd);
            unlink(SUPP_CONFIG_FILE);
            return -1;
        }
        write(destfd, buf, nread);
    }

    close(destfd);
    close(srcfd);

    if (chown(SUPP_CONFIG_FILE, AID_SYSTEM, AID_WIFI) < 0) {
        LOGE("Error changing group ownership of %s to %d: %s",
             SUPP_CONFIG_FILE, AID_WIFI, strerror(errno));
        unlink(SUPP_CONFIG_FILE);
        return -1;
    }
    return 0;
}

int Supplicant::setNetworkVar(int networkId, const char *var, const char *val) {
    char reply[255];
    size_t len = sizeof(reply) -1;

    char *tmp;
    asprintf(&tmp, "SET_NETWORK %d %s \"%s\"", networkId, var, val);
    if (sendCommand(tmp, reply, &len)) {
        free(tmp);
        return -1;
    }
    free(tmp);
    return 0;
}

const char *Supplicant::getNetworkVar(int networkId, const char *var,
                                      char *buffer, size_t max) {
    size_t len = max - 1;
    char *tmp;

    asprintf(&tmp, "GET_NETWORK %d %s", networkId, var);
    if (sendCommand(tmp, buffer, &len)) {
        free(tmp);
        return NULL;
    }
    free(tmp);
    return buffer;
}

int Supplicant::enableNetwork(int networkId, bool enabled) {
    char req[64];

    if (enabled)
        sprintf(req, "ENABLE_NETWORK %d", networkId);
    else
        sprintf(req, "DISABLE_NETWORK %d", networkId);

    char reply[16];
    size_t len = sizeof(reply) -1;

    if (sendCommand(req, reply, &len))
        return -1;
    return 0;
}


int Supplicant::retrieveInterfaceName() {
    char reply[255];
    size_t len = sizeof(reply) -1;

    if (sendCommand("INTERFACES", reply, &len))
        return -1;

    reply[strlen(reply)-1] = '\0';
    mInterfaceName = strdup(reply);
    return 0;
}
