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

#define LOG_TAG "SupplicantState"
#include <cutils/log.h>

#include "SupplicantStatus.h"
#include "SupplicantState.h"

SupplicantStatus::SupplicantStatus() {
    mWpaState = SupplicantState::UNKNOWN;
    mId = -1;
    mBssid = NULL;
    mSsid = NULL;
}

SupplicantStatus::SupplicantStatus(int state, int id, char *bssid, char *ssid) :
                  mWpaState(state), mId(id), mBssid(bssid), mSsid(ssid) {

LOGD("state %d, id %d, bssid %p, ssid %p\n", mWpaState, mId, mBssid, mSsid);
}

SupplicantStatus::~SupplicantStatus() {
    if (mBssid)
        free(mBssid);
    if (mSsid)
        free(mSsid);
}

SupplicantStatus *SupplicantStatus::createStatus(char *data, int len) {
    char *bssid = NULL;
    char *ssid = NULL;
    int id = -1;
    int state = SupplicantState::UNKNOWN;

    char *next = data;
    char *line;
    while((line = strsep(&next, "\n"))) {
        char *token = strsep(&next, "=");
        char *value = strsep(&next, "=");

        if (!strcmp(token, "bssid"))
            bssid = strdup(value);
        else if (!strcmp(token, "ssid"))
            ssid = strdup(value);
        else if (!strcmp(token, "id"))
            id = atoi(value);
        else if (!strcmp(token, "wpa_state"))
            state = atoi(value);
        else
            LOGD("Ignoring unsupported status token '%s'", token);
    }

    return new SupplicantStatus(state, id, bssid, ssid);
    
}
