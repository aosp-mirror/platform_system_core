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

#define LOG_TAG "SupplicantConnectedEvent"
#include <cutils/log.h>

#include "SupplicantConnectedEvent.h"

SupplicantConnectedEvent::SupplicantConnectedEvent(int level, char *event,
                                                   size_t len) :
                          SupplicantEvent(SupplicantEvent::EVENT_CONNECTED,
                                          level) {
    char *p;

    //  "- Connection to 00:13:46:40:40:aa completed (auth) [id=1 id_str=], 89"
    
    if ((p = index(event + 2, ' ')) && (++p = index(p, ' '))) {
        mBssid = (char *) malloc(18);
        strncpy(mBssid, ++p, 17);
        mBssid[17] = '\0';

        //  "- Connection to 00:13:46:40:40:aa completed (auth) [id=1 id_str=], 89"
        //                   ^
        //                   p
        
        if ((p = index(p, ' ')) && ((++p = index(p, ' ')))) {
            if (!strncmp(++p, "(auth)", 6))
                mReassociated = false;
            else
                mReassociated = true;
        } else
            LOGE("Unable to decode re-assocation");
    } else
        LOGE("Unable to decode event");
}

SupplicantConnectedEvent::SupplicantConnectedEvent(const char *bssid, 
                                                   bool reassocated) :
                          SupplicantEvent(SupplicantEvent::EVENT_CONNECTED, -1) {
    mBssid = strdup(bssid);
    mReassociated = reassocated;
}

SupplicantConnectedEvent::~SupplicantConnectedEvent() {
    if (mBssid)
        free(mBssid);
}

