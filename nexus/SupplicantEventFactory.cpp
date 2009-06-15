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

#define LOG_TAG "SupplicantEventFactory"
#include <cutils/log.h>

#include "SupplicantEvent.h"
#include "SupplicantEventFactory.h"
#include "SupplicantAssociatingEvent.h"
#include "SupplicantAssociatedEvent.h"
#include "SupplicantConnectedEvent.h"
#include "SupplicantStateChangeEvent.h"
#include "SupplicantScanResultsEvent.h"
#include "SupplicantConnectionTimeoutEvent.h"
#include "SupplicantDisconnectedEvent.h"
#if 0
#include "SupplicantTerminatingEvent.h"
#include "SupplicantPasswordChangedEvent.h"
#include "SupplicantEapNotificationEvent.h"
#include "SupplicantEapStartedEvent.h"
#include "SupplicantEapMethodEvent.h"
#include "SupplicantEapSuccessEvent.h"
#include "SupplicantEapFailureEvent.h"
#include "SupplicantLinkSpeedEvent.h"
#include "SupplicantDriverStateEvent.h"
#endif

#include "libwpa_client/wpa_ctrl.h"

SupplicantEventFactory::SupplicantEventFactory() {
}

SupplicantEvent *SupplicantEventFactory::createEvent(char *event, size_t len) {
    int level = 0;

    if (event[0] == '<') {
        char *match = strchr(event, '>');
        if (match) {
            char tmp[16];

            strncpy(tmp, &event[1], (match - event));
            level = atoi(tmp);
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

    if (!strncmp(event, "Authentication with ", 20)) {
        if (!strcmp(event + strlen(event) - strlen(" timed out."),
                    " timed out.")) {
            return new SupplicantConnectionTimeoutEvent(level,
                                                        event + 20,
                                                        len);
        } else
            return NULL;
        
    } else if (!strncmp(event, "Associated with ", 16))
        return new SupplicantAssociatedEvent(level, event + 16, len);
    else if (!strncmp(event, "Trying to associate with ", 25))
        return new SupplicantAssociatingEvent(level, event + 25, len);
    else if (!strncmp(event, WPA_EVENT_CONNECTED, strlen(WPA_EVENT_CONNECTED))) {
        return new SupplicantConnectedEvent(level,
                                            event + strlen(WPA_EVENT_CONNECTED),
                                            len);
    } else if (!strncmp(event, WPA_EVENT_SCAN_RESULTS, strlen(WPA_EVENT_SCAN_RESULTS))) {
        return new SupplicantScanResultsEvent(level,
                                              event + strlen(WPA_EVENT_SCAN_RESULTS),
                                              len);
    } else if (!strncmp(event, WPA_EVENT_STATE_CHANGE, strlen(WPA_EVENT_STATE_CHANGE))) {
        return new SupplicantStateChangeEvent(level,
                                              event + strlen(WPA_EVENT_STATE_CHANGE),
                                              len);
    }
    else if (!strncmp(event, WPA_EVENT_DISCONNECTED, strlen(WPA_EVENT_DISCONNECTED)))
        return new SupplicantDisconnectedEvent(level, event, len);
#if 0
    else if (!strncmp(event, WPA_EVENT_TERMINATING, strlen(WPA_EVENT_TERMINATING)))
        return new SupplicantTerminatingEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_PASSWORD_CHANGED, strlen(WPA_EVENT_PASSWORD_CHANGED)))
        return new SupplicantPasswordChangedEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_EAP_NOTIFICATION, strlen(WPA_EVENT_EAP_NOTIFICATION)))
        return new SupplicantEapNotificationEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_EAP_STARTED, strlen(WPA_EVENT_EAP_STARTED)))
        return new SupplicantEapStartedEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_EAP_METHOD, strlen(WPA_EVENT_EAP_METHOD)))
        return new SupplicantEapMethodEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_EAP_SUCCESS, strlen(WPA_EVENT_EAP_SUCCESS)))
        return new SupplicantEapSuccessEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_EAP_FAILURE, strlen(WPA_EVENT_EAP_FAILURE)))
        return new SupplicantEapFailureEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_LINK_SPEED, strlen(WPA_EVENT_LINK_SPEED)))
        return new SupplicantLinkSpeedEvent(event, len);
    else if (!strncmp(event, WPA_EVENT_DRIVER_STATE, strlen(WPA_EVENT_DRIVER_STATE)))
         return new SupplicantDriverStateEvent(event, len);
#endif
    return NULL;
}
