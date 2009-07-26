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

#define LOG_TAG "SupplicantAssociatingEvent"
#include <cutils/log.h>

#include "SupplicantAssociatingEvent.h"

SupplicantAssociatingEvent::SupplicantAssociatingEvent(int level, char *event,
                                                     size_t len) :
                           SupplicantEvent(SupplicantEvent::EVENT_ASSOCIATING,
                                           level) {
    char *p = event;

    mBssid = NULL;
    mSsid = NULL;
    mFreq = -1;

    // SSID 'default' 
    // OR
    // "00:13:46:40:40:aa (SSID='default' freq=2437 MHz)"

    if (strncmp(event, "SSID", 4)) {
        mBssid = (char *) malloc(18);
        strncpy(mBssid, p, 17);
        mBssid[17] = '\0';
        p += 25;

        // "00:13:46:40:40:aa (SSID='default' freq=2437 MHz)"
        //                           ^
        //                           p
        char *q = index(p, '\'');
        if (!q) {
            LOGE("Unable to decode SSID (p = {%s})\n", p);
            return;
        }
        mSsid = (char *) malloc((q - p) +1);
        strncpy(mSsid, p, q-p);
        mSsid[q-p] = '\0';

        p = q + 7;
    
        // "00:13:46:40:40:aa (SSID='default' freq=2437 MHz)"
        //                                         ^
        //                                         p
        if (!(q = index(p, ' '))) {
            LOGE("Unable to decode frequency\n");
            return;
        }
        *q = '\0';
        mFreq = atoi(p);
    } else {
        p+= 6;

        // SSID 'default' 
        //       ^
        //       p

        char *q = index(p, '\'');
        if (!q) {
            LOGE("Unable to decode SSID (p = {%s})\n", p);
            return;
        }
        mSsid = (char *) malloc((q - p) +1);
        strncpy(mSsid, p, q-p);
        mSsid[q-p] = '\0';
    }
}

SupplicantAssociatingEvent::SupplicantAssociatingEvent(const char *bssid, 
                                                     const char *ssid,
                                                     int freq) :
                           SupplicantEvent(SupplicantEvent::EVENT_ASSOCIATING, -1) {
    mBssid = strdup(bssid);
    mSsid= strdup(ssid);
    mFreq = freq;
}

SupplicantAssociatingEvent::~SupplicantAssociatingEvent() {
    if (mBssid)
        free(mBssid);
    if (mSsid)
        free(mSsid);
}

