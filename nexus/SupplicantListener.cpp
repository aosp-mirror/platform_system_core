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

#include "SupplicantListener.h"
#include "ISupplicantEventHandler.h"
#include "SupplicantEventFactory.h"
#include "SupplicantEvent.h"
#include "SupplicantAssociatingEvent.h"
#include "SupplicantAssociatedEvent.h"
#include "SupplicantConnectedEvent.h"
#include "SupplicantScanResultsEvent.h"
#include "SupplicantStateChangeEvent.h"

SupplicantListener::SupplicantListener(ISupplicantEventHandler *handlers, 
                                       struct wpa_ctrl *monitor) :
                    SocketListener(wpa_ctrl_get_fd(monitor), false) {
    mHandlers = handlers;
    mMonitor = monitor;
    mFactory = new SupplicantEventFactory();
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

    SupplicantEvent *evt = mFactory->createEvent(buf, nread);

    if (!evt) {
        LOGW("Dropping unknown supplicant event '%s'", buf);
        return true;
    }

    // Call the appropriate handler
    if (evt->getType() == SupplicantEvent::EVENT_ASSOCIATING)
        mHandlers->onAssociatingEvent((SupplicantAssociatingEvent *) evt);
    else if (evt->getType() == SupplicantEvent::EVENT_ASSOCIATED)
        mHandlers->onAssociatedEvent((SupplicantAssociatedEvent *) evt);
    else if (evt->getType() == SupplicantEvent::EVENT_CONNECTED)
        mHandlers->onConnectedEvent((SupplicantConnectedEvent *) evt);
    else if (evt->getType() == SupplicantEvent::EVENT_SCAN_RESULTS)
        mHandlers->onScanResultsEvent((SupplicantScanResultsEvent *) evt);
    else if (evt->getType() == SupplicantEvent::EVENT_STATE_CHANGE)
        mHandlers->onStateChangeEvent((SupplicantStateChangeEvent *) evt);
    else if (evt->getType() == SupplicantEvent::EVENT_CONNECTIONTIMEOUT)
        mHandlers->onConnectionTimeoutEvent((SupplicantConnectionTimeoutEvent *) evt);
    else if (evt->getType() == SupplicantEvent::EVENT_DISCONNECTED)
        mHandlers->onDisconnectedEvent((SupplicantDisconnectedEvent *) evt);
    else
        LOGW("Whoops - no handler available for event '%s'\n", buf);
#if 0
    else if (evt->getType() == SupplicantEvent::EVENT_TERMINATING)
        mHandlers->onTerminatingEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_PASSWORD_CHANGED)
        mHandlers->onPasswordChangedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_NOTIFICATION)
        mHandlers->onEapNotificationEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_STARTED)
        mHandlers->onEapStartedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_SUCCESS)
        mHandlers->onEapSuccessEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_EAP_FAILURE)
        mHandlers->onEapFailureEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_LINK_SPEED)
        mHandlers->onLinkSpeedEvent(evt);
    else if (evt->getType() == SupplicantEvent::EVENT_DRIVER_STATE)
        mHandlers->onDriverStateEvent(evt);
#endif

    delete evt;

    return true;
}
