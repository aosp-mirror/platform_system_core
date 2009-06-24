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
#include "NetworkManager.h"
#include "WifiController.h"
#include "SupplicantStatus.h"

#include "libwpa_client/wpa_ctrl.h"

#define IFACE_DIR        "/data/system/wpa_supplicant"
#define DRIVER_PROP_NAME "wlan.driver.status"
#define SUPPLICANT_SERVICE_NAME  "wpa_supplicant"
#define SUPP_CONFIG_TEMPLATE "/system/etc/wifi/wpa_supplicant.conf"
#define SUPP_CONFIG_FILE "/data/misc/wifi/wpa_supplicant.conf"

Supplicant::Supplicant(WifiController *wc, ISupplicantEventHandler *handlers) {
    mHandlers = handlers;
    mController = wc;
    mInterfaceName = NULL;
    mCtrl = NULL;
    mMonitor = NULL;
    mListener = NULL;
   
    mServiceManager = new ServiceManager();

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

    return 0;
}

int Supplicant::stop() {

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

int Supplicant::sendCommand(const char *cmd, char *reply, size_t *reply_len) {

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
SupplicantStatus *Supplicant::getStatus() {
    char *reply;
    size_t len = 4096;

    if (!(reply = (char *) malloc(len))) {
        errno = ENOMEM;
        return NULL;
    }

    if (sendCommand("STATUS", reply, &len)) {
        free(reply);
        return NULL;
    }

    SupplicantStatus *ss = SupplicantStatus::createStatus(reply, len);
  
    free (reply);
    return ss;
}

/*
 * Retrieves the list of networks from Supplicant
 * and merge them into our current list
 */
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
        free(reply);
        errno = EIO;
        return -1;
    }

    PropertyManager *pm = NetworkManager::Instance()->getPropMngr();
    pthread_mutex_lock(&mNetworksLock);

    int num_added = 0;
    int num_refreshed = 0;
    int num_removed = 0;
    while((linep = strtok_r(NULL, "\n", &linep_next))) {
        // TODO: Move the decode into a static method so we
        // don't create new_wn when we don't have to.
        WifiNetwork *new_wn = new WifiNetwork(mController, this, linep);
        WifiNetwork *merge_wn;

        if ((merge_wn = this->lookupNetwork_UNLOCKED(new_wn->getNetworkId()))) {
            num_refreshed++;
            if (merge_wn->refresh()) {
                LOGW("Error refreshing network %d (%s)",
                     merge_wn->getNetworkId(), strerror(errno));
                }
            delete new_wn;
        } else {
            num_added++;
            char new_ns[20];
            snprintf(new_ns, sizeof(new_ns), "wifi.net.%d", new_wn->getNetworkId());
            new_wn->attachProperties(pm, new_ns);
            mNetworks->push_back(new_wn);
            if (new_wn->refresh()) {
                LOGW("Unable to refresh network id %d (%s)",
                    new_wn->getNetworkId(), strerror(errno));
            }
        }
    }

    if (!mNetworks->empty()) {
        // TODO: Add support for detecting removed networks
        WifiNetworkCollection::iterator i;

        for (i = mNetworks->begin(); i != mNetworks->end(); ++i) {
            if (0) {
                num_removed++;
                char del_ns[20];
                snprintf(del_ns, sizeof(del_ns), "wifi.net.%d", (*i)->getNetworkId());
                (*i)->detachProperties(pm, del_ns);
                delete (*i);
                i = mNetworks->erase(i);
            }
        }
    }


    LOGD("Networks added %d, refreshed %d, removed %d\n", 
         num_added, num_refreshed, num_removed);
    pthread_mutex_unlock(&mNetworksLock);

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

    mListener = new SupplicantListener(mHandlers, mMonitor);

    if (mListener->startListener()) {
        LOGE("Error - unable to start supplicant listener");
        stop();
        return -1;
    }
    return 0;
}

int Supplicant::setScanMode(bool active) {
    char reply[255];
    size_t len = sizeof(reply);

    if (sendCommand((active ? "DRIVER SCAN-ACTIVE" : "DRIVER SCAN-PASSIVE"),
                     reply, &len)) {
        LOGW("triggerScan(%d): Error setting scan mode (%s)", active,
             strerror(errno));
        return -1;
    }
    return 0;
}

int Supplicant::triggerScan() {
    char reply[255];
    size_t len = sizeof(reply);

    if (sendCommand("SCAN", reply, &len)) {
        LOGW("triggerScan(): Error initiating scan");
        return -1;
    }
    return 0;
}

int Supplicant::getRssi(int *buffer) {
    char reply[64];
    size_t len = sizeof(reply);

    if (sendCommand("DRIVER RSSI", reply, &len)) {
        LOGW("Failed to get RSSI (%s)", strerror(errno));
        return -1;
    }

    char *next = reply;
    char *s;
    for (int i = 0; i < 3; i++) {
        if (!(s = strsep(&next, " "))) {
            LOGE("Error parsing RSSI");
            errno = EIO;
            return -1;
        }
    }
    *buffer = atoi(s);
    return 0;
}

int Supplicant::getLinkSpeed() {
    char reply[64];
    size_t len = sizeof(reply);

    if (sendCommand("DRIVER LINKSPEED", reply, &len)) {
        LOGW("Failed to get LINKSPEED (%s)", strerror(errno));
        return -1;
    }

    char *next = reply;
    char *s;

    if (!(s = strsep(&next, " "))) {
        LOGE("Error parsing LINKSPEED");
        errno = EIO;
        return -1;
    }

    if (!(s = strsep(&next, " "))) {
        LOGE("Error parsing LINKSPEED");
        errno = EIO;
        return -1;
    }
    return atoi(s);
}

int Supplicant::stopDriver() {
    char reply[64];
    size_t len = sizeof(reply);

    LOGD("stopDriver()");

    if (sendCommand("DRIVER STOP", reply, &len)) {
        LOGW("Failed to stop driver (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

int Supplicant::startDriver() {
    char reply[64];
    size_t len = sizeof(reply);

    LOGD("startDriver()");
    if (sendCommand("DRIVER START", reply, &len)) {
        LOGW("Failed to start driver (%s)", strerror(errno));
        return -1;
    }
    return 0;
}

WifiNetwork *Supplicant::createNetwork() {
    char reply[255];
    size_t len = sizeof(reply) -1;

    if (sendCommand("ADD_NETWORK", reply, &len))
        return NULL;

    if (reply[strlen(reply) -1] == '\n')
        reply[strlen(reply) -1] = '\0';

    WifiNetwork *wn = new WifiNetwork(mController, this, atoi(reply));
    PropertyManager *pm = NetworkManager::Instance()->getPropMngr();
    pthread_mutex_lock(&mNetworksLock);
    char new_ns[20];
    snprintf(new_ns, sizeof(new_ns), "wifi.net.%d", wn->getNetworkId());
    wn->attachProperties(pm, new_ns);
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
    WifiNetwork *wn = lookupNetwork_UNLOCKED(networkId);
    pthread_mutex_unlock(&mNetworksLock);
    return wn;
}

WifiNetwork *Supplicant::lookupNetwork_UNLOCKED(int networkId) {
    WifiNetworkCollection::iterator it;
    for (it = mNetworks->begin(); it != mNetworks->end(); ++it) {
        if ((*it)->getNetworkId() == networkId) {
            return *it;
        }
    }
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

    LOGD("netid %d, var '%s' = '%s'", networkId, var, val);
    char *tmp;
    asprintf(&tmp, "SET_NETWORK %d %s %s", networkId, var, val);
    if (sendCommand(tmp, reply, &len)) {
        free(tmp);
        return -1;
    }
    free(tmp);

    len = sizeof(reply) -1;
    if (sendCommand("SAVE_CONFIG", reply, &len)) {
        LOGE("Error saving config after %s = %s", var, val);
        return -1;
    }
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

int Supplicant::enablePacketFilter() {
    char req[128];
    char reply[16];
    size_t len;
    int i;
    
    for (i = 0; i <=3; i++) {
        snprintf(req, sizeof(req), "DRIVER RXFILTER-ADD %d", i);
        len = sizeof(reply);
        if (sendCommand(req, reply, &len))
            return -1;
    }

    len = sizeof(reply);
    if (sendCommand("DRIVER RXFILTER-START", reply, &len))
        return -1;
    return 0;
}
  
int Supplicant::disablePacketFilter() {
    char req[128];
    char reply[16];
    size_t len;
    int i;
    
    len = sizeof(reply);
    if (sendCommand("DRIVER RXFILTER-STOP", reply, &len))
        return -1;

    for (i = 3; i >=0; i--) {
        snprintf(req, sizeof(req), "DRIVER RXFILTER-REMOVE %d", i);
        len = sizeof(reply);
        if (sendCommand(req, reply, &len))
            return -1;
    }
    return 0;
}

int Supplicant::enableBluetoothCoexistenceScan() {
    char req[128];
    char reply[16];
    size_t len;
    int i;
    
    len = sizeof(reply);
    if (sendCommand("DRIVER BTCOEXSCAN-START", reply, &len))
        return -1;
    return 0;
}

int Supplicant::disableBluetoothCoexistenceScan() {
    char req[128];
    char reply[16];
    size_t len;
    int i;
    
    len = sizeof(reply);
    if (sendCommand("DRIVER BTCOEXSCAN-STOP", reply, &len))
        return -1;
    return 0;
}

int Supplicant::setBluetoothCoexistenceMode(int mode) {
    char req[64];

    sprintf(req, "DRIVER BTCOEXMODE %d", mode);

    char reply[16];
    size_t len = sizeof(reply) -1;

    if (sendCommand(req, reply, &len))
        return -1;
    return 0;
}

int Supplicant::setApScanMode(int mode) {
    char req[64];

//    LOGD("setApScanMode(%d)", mode);
    sprintf(req, "AP_SCAN %d", mode);

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

int Supplicant::reconnect() {
    char req[128];
    char reply[16];
    size_t len;
    int i;
    
    len = sizeof(reply);
    if (sendCommand("RECONNECT", reply, &len))
        return -1;
    return 0;
}

int Supplicant::disconnect() {
    char req[128];
    char reply[16];
    size_t len;
    int i;
    
    len = sizeof(reply);
    if (sendCommand("DISCONNECT", reply, &len))
        return -1;
    return 0;
}

int Supplicant::getNetworkCount() {
    pthread_mutex_lock(&mNetworksLock);
    int cnt = mNetworks->size();
    pthread_mutex_unlock(&mNetworksLock);
    return cnt;
}
