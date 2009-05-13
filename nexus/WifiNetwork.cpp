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
#include <string.h>
#include <sys/types.h>

#include "WifiNetwork.h"
#include "Supplicant.h"

WifiNetwork::WifiNetwork(Supplicant *suppl) {
    mSuppl = suppl;
    mNetid = -1;
    mSsid = NULL;
    mBssid = NULL;
    mPsk = NULL;
    memset(mWepKeys, 0, sizeof(mWepKeys));
    mDefaultKeyIndex = -1;
    mPriority = -1;
    mHiddenSsid = NULL;
    mAllowedKeyManagement = 0;
    mAllowedProtocols = 0;
    mAllowedAuthAlgorithms = 0;
    mAllowedPairwiseCiphers = 0;
    mAllowedGroupCiphers = 0;
}

WifiNetwork::~WifiNetwork() {
    if (mSsid)
        free(mSsid);
    if (mBssid)
        free(mBssid);
    if (mPsk)
        free(mPsk);
    for (int i = 0; i < 4; i++) {
        if (mWepKeys[i])
            free(mWepKeys[i]);
    }
    if (mHiddenSsid)
        free(mHiddenSsid);
}

int WifiNetwork::setSsid(char *ssid) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setBssid(char *bssid) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setPsk(char *psk) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setWepKey(int idx, char *key) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setDefaultKeyIndex(int idx) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setPriority(int idx) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setHiddenSsid(char *ssid) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setAllowedKeyManagement(uint32_t mask) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setAllowedProtocols(uint32_t mask) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setAllowedPairwiseCiphers(uint32_t mask) {
    errno = ENOSYS;
    return -1;
}

int WifiNetwork::setAllowedGroupCiphers(uint32_t mask) {
    errno = ENOSYS;
    return -1;
}
