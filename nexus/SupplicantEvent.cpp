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

#define LOG_TAG "SupplicantEvent"
#include <cutils/log.h>

#include "SupplicantEvent.h"

#include "libwpa_client/wpa_ctrl.h"

SupplicantEvent::SupplicantEvent(char *event, size_t len) {

    if (event[0] == '<') {
        char *match = strchr(event, '>');
        if (match) {
            char tmp[16];

            strncpy(tmp, &event[1], (match - event));
            mLevel = atoi(tmp);
            event += (match - event) + 1;
        } else
            LOGW("Unclosed level brace in event");
    } else
        LOGW("No level specified in event");

    /*
     * <N>CTRL-EVENT-XXX
     *    ^
     *    +---- event
     */

    if (!strncmp(event, WPA_EVENT_CONNECTED, strlen(WPA_EVENT_CONNECTED)))
        mType = SupplicantEvent::EVENT_CONNECTED;
    else if (!strncmp(event, WPA_EVENT_DISCONNECTED, strlen(WPA_EVENT_DISCONNECTED)))
        mType = SupplicantEvent::EVENT_DISCONNECTED;
    else if (!strncmp(event, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING)))
        mType = SupplicantEvent::EVENT_TERMINATING;
    else if (!strncmp(event, WPA_EVENT_PASSWORD_CHANGED, strlen(WPA_EVENT_PASSWORD_CHANGED)))
        mType = SupplicantEvent::EVENT_PASSWORD_CHANGED;
    else if (!strncmp(event, WPA_EVENT_EAP_NOTIFICATION, strlen(WPA_EVENT_EAP_NOTIFICATION)))
        mType = SupplicantEvent::EVENT_EAP_NOTIFICATION;
    else if (!strncmp(event, WPA_EVENT_EAP_STARTED, strlen(WPA_EVENT_EAP_STARTED)))
        mType = SupplicantEvent::EVENT_EAP_STARTED;
    else if (!strncmp(event, WPA_EVENT_EAP_METHOD, strlen(WPA_EVENT_EAP_METHOD)))
        mType = SupplicantEvent::EVENT_EAP_METHOD;
    else if (!strncmp(event, WPA_EVENT_EAP_SUCCESS, strlen(WPA_EVENT_EAP_SUCCESS)))
        mType = SupplicantEvent::EVENT_EAP_SUCCESS;
    else if (!strncmp(event, WPA_EVENT_EAP_FAILURE, strlen(WPA_EVENT_EAP_FAILURE)))
        mType = SupplicantEvent::EVENT_EAP_FAILURE;
    else if (!strncmp(event, WPA_EVENT_SCAN_RESULTS, strlen(WPA_EVENT_SCAN_RESULTS)))
        mType = SupplicantEvent::EVENT_SCAN_RESULTS;
    else if (!strncmp(event, WPA_EVENT_STATE_CHANGE, strlen(WPA_EVENT_STATE_CHANGE)))
        mType = SupplicantEvent::EVENT_STATE_CHANGE;
    else if (!strncmp(event, WPA_EVENT_LINK_SPEED, strlen(WPA_EVENT_LINK_SPEED)))
        mType = SupplicantEvent::EVENT_LINK_SPEED;
    else if (!strncmp(event, WPA_EVENT_DRIVER_STATE, strlen(WPA_EVENT_DRIVER_STATE)))
        mType = SupplicantEvent::EVENT_DRIVER_STATE;
    else {
        LOGW("Unknown supplicant event '%s'", event);
        mType = SupplicantEvent::EVENT_UNKNOWN;
    }

    for (event; *event != ' '; event++);
    event++;

    /*
     * <N>CTRL-EVENT-XXX YYYY
     *                   ^
     *                   +---- event
     */

    for (event; *event == ' '; event++);

    mEvent = strdup(event);
    mLen = len;
}

SupplicantEvent::~SupplicantEvent() {
    if (mEvent)
        free(mEvent);
}
