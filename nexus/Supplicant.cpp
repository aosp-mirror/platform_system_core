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
#include <errno.h>

#define LOG_TAG "Supplicant"
#include <cutils/log.h>
#include <cutils/properties.h>

#undef HAVE_LIBC_SYSTEM_PROPERTIES

#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
#define _REALLY_INCLUDE_SYS__SYSTEM_PROPERTIES_H_
#include <sys/_system_properties.h>
#endif

#include "Supplicant.h"
#include "SupplicantListener.h"
#include "SupplicantState.h"
#include "SupplicantEvent.h"
#include "ScanResult.h"

#include "libwpa_client/wpa_ctrl.h"

#define IFACE_DIR        "/data/system/wpa_supplicant"
#define DRIVER_PROP_NAME "wlan.driver.status"
#define SUPPLICANT_NAME  "wpa_supplicant"
#define SUPP_PROP_NAME   "init.svc.wpa_supplicant"

Supplicant::Supplicant() {
    mCtrl = NULL;
    mMonitor = NULL;
    mListener = NULL;

    mState = SupplicantState::UNKNOWN;

    mLatestScanResults = new ScanResultCollection();

    pthread_mutex_init(&mLatestScanResultsLock, NULL);
}

int Supplicant::start() {
    LOGD("start():");
    // XXX: Validate supplicant config file
    
    char status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 200;
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    const prop_info *pi;
    unsigned int serial = 0;
#endif

    if (property_get(SUPP_PROP_NAME, status, NULL) &&
        strcmp(status, "running") == 0) {
        return 0;
    }

    wpa_ctrl_cleanup();
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
    pi = __system_property_find(SUPP_PROP_NAME);
    if (pi != NULL)
        serial = pi->serial;
#endif

    property_set("ctl.start", SUPPLICANT_NAME);
    sched_yield();
    while (count--) {
#ifdef HAVE_LIBC_SYSTEM_PROPERTIES
        if (!pi)
            pi = __system_property_find(SUPP_PROP_NAME);
        if (pi) {
            __system_property_read(pi, NULL, status);
            if (strcmp(status, "running") == 0)
                return 0;
            else if (pi->serial != serial &&
                    strcmp(status, "stopped") == 0) {
                errno = EIO;
                return -1;
            }
        }
#else
        if (property_get(SUPP_PROP_NAME, status, NULL)) {
            if (strcmp(status, "running") == 0)
                break;
        }
#endif
        usleep(100000);
    }

    if (!count) {
        errno = ETIMEDOUT;
        return -1;
    }
  
    if (connectToSupplicant()) {
        LOGE("Error connecting to supplicant (%s)\n", strerror(errno));
        return -1;
    }
    return 0;
}

int Supplicant::stop() {
    LOGD("stop()");

    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50; 

    if (mListener->stopListener()) {
        LOGW("Unable to stop supplicant listener (%s)", strerror(errno));
        return -1;
    }

    if (property_get(SUPP_PROP_NAME, supp_status, NULL)
        && strcmp(supp_status, "stopped") == 0) {
        return 0;
    }

    property_set("ctl.stop", SUPPLICANT_NAME);
    sched_yield();

    while (count-- > 0) {
        if (property_get(SUPP_PROP_NAME, supp_status, NULL)) {
            if (strcmp(supp_status, "stopped") == 0)
                break;
        }
        usleep(100000);
    }

    if (mCtrl) {
        wpa_ctrl_close(mCtrl);
        mCtrl = NULL;
    }
    if (mMonitor) {
        wpa_ctrl_close(mMonitor);
        mMonitor = NULL;
    }

    if (!count) {
        LOGD("Timed out waiting for supplicant to stop");
        errno = ETIMEDOUT;
        return -1;
    }

    LOGD("Stopped OK");

    return 0;
}

bool Supplicant::isStarted() {
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};
    if (!property_get(SUPP_PROP_NAME, supp_status, NULL) ||
        !strcmp(supp_status, "running")) {
        return false;
    }
    return true;
}

int Supplicant::connectToSupplicant() {
    char ifname[256];
    char supp_status[PROPERTY_VALUE_MAX] = {'\0'};

    if (!property_get(SUPP_PROP_NAME, supp_status, NULL)
            || strcmp(supp_status, "running") != 0) {
        LOGE("Supplicant not running, cannot connect");
        return -1;
    }

    mCtrl = wpa_ctrl_open("tiwlan0");
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

    LOGD("sendCommand(): -> '%s'", cmd);

    int rc;
    if ((rc = wpa_ctrl_request(mCtrl, cmd, strlen(cmd), reply, reply_len, NULL)) == -2)  {
        errno = ETIMEDOUT;
        return -1;
    } else if (rc < 0 || !strncmp(reply, "FAIL", 4)) {
        errno = EIO;
        return -1;
    }

    if (!strncmp(cmd, "PING", 4) ||
        !strncmp(cmd, "SCAN_RESULTS", 12)) 
        reply[*reply_len] = '\0';

    LOGD("sendCommand(): <- '%s'", reply);
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
    LOGD("onScanResultsEvent(%s)", evt->getEvent());

    if (!strcmp(evt->getEvent(), "Ready")) {
        char *reply;

        if (!(reply = (char *) malloc(4096))) {
            errno = -ENOMEM;
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
            return 0;;
        }

        while((linep = strtok_r(NULL, "\n", &linep_next)))
            mLatestScanResults->push_back(new ScanResult(linep));

        pthread_mutex_unlock(&mLatestScanResultsLock);
        free(reply);
    } else {
        LOGW("Unknown SCAN_RESULTS event (%s)", evt->getEvent());
    }
    return 0;
}

int Supplicant::onStateChangeEvent(SupplicantEvent *evt) {
    LOGD("onStateChangeEvent(%s)", evt->getEvent());
    // XXX: Update mState
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
const ScanResultCollection *Supplicant::getLatestScanResults() {
    ScanResultCollection *d = new ScanResultCollection();
    ScanResultCollection::iterator i;

    pthread_mutex_lock(&mLatestScanResultsLock);
    for (i = mLatestScanResults->begin(); i != mLatestScanResults->end(); ++i) {
        d->push_back((*i)->clone());
    }

    pthread_mutex_unlock(&mLatestScanResultsLock);
    return d;
};
