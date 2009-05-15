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
#include <sys/types.h>
#include <pthread.h>

#define LOG_TAG "SupplicantListener"
#include <cutils/log.h>

#include "libwpa_client/wpa_ctrl.h"

#include "Supplicant.h"
#include "SupplicantListener.h"
#include "SupplicantEvent.h"

SupplicantListener::SupplicantListener(Supplicant *supplicant, struct wpa_ctrl *monitor) :
                    SocketListener(wpa_ctrl_get_fd(monitor), false) {
    mSupplicant = supplicant;
    mMonitor = monitor;
}

bool SupplicantListener::onDataAvailable(SocketClient *cli) {
    char buf[255];
    size_t buflen = sizeof(buf);
    int rc;
    size_t nread = buflen - 1;

    if ((rc = wpa_ctrl_recv(mMonitor, buf, &nread))) {
        LOGE("wpa_ctrl_recv failed (%s)", strerror(errno));
        return false;
    }

    buf[nread] = '\0';
    if (!rc && !nread) {
        LOGD("Received EOF on supplicant socket\n");
        strncpy(buf, WPA_EVENT_TERMINATING " - signal 0 received", buflen-1);
        buf[buflen-1] = '\0';
        return false;
    }

    SupplicantEvent *evt = new SupplicantEvent(buf, nread);

    // XXX: Make this a factory
    // XXX: Instead of calling Supplicant directly
    // extract an Interface and use that instead
    if (evt->getType() == SupplicantEvent::EVENT_CONNECTED)
        rc = mSupplicant->onConnectedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_DISCONNECTED)
        rc = mSupplicant->onDisconnectedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_TERMINATING)
        rc = mSupplicant->onTerminatingEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_PASSWORD_CHANGED)
        rc = mSupplicant->onPasswordChangedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_NOTIFICATION)
        rc = mSupplicant->onEapNotificationEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_STARTED)
        rc = mSupplicant->onEapStartedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_SUCCESS)
        rc = mSupplicant->onEapSuccessEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_FAILURE)
        rc = mSupplicant->onEapFailureEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_SCAN_RESULTS)
        rc = mSupplicant->onScanResultsEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_STATE_CHANGE)
        rc = mSupplicant->onStateChangeEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_LINK_SPEED)
        rc = mSupplicant->onLinkSpeedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_DRIVER_STATE)
        rc = mSupplicant->onDriverStateEvent(evt);
    else {
        LOGW("Ignoring unknown event");
    }

    delete evt;
    
    if (rc) {
        LOGW("Handler %d (%s) error: %s", evt->getType(), evt->getEvent(), strerror(errno));
        return false;
    }
    return true;
}
