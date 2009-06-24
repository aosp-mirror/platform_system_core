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
#include <stdlib.h>
#include <sys/types.h>

#define LOG_TAG "WifiNetwork"
#include <cutils/log.h>

#include "NetworkManager.h"
#include "WifiNetwork.h"
#include "Supplicant.h"
#include "WifiController.h"

WifiNetwork::WifiNetwork() {
   // This is private to restrict copy constructors
}

WifiNetwork::WifiNetwork(WifiController *c, Supplicant *suppl, const char *data) {
    mController = c;
    mSuppl = suppl;

    char *tmp = strdup(data);
    char *next = tmp;
    char *id;
    char *ssid;
    char *bssid;
    char *flags;

    if (!(id = strsep(&next, "\t")))
        LOGE("Failed to extract network id");
    if (!(ssid = strsep(&next, "\t")))
        LOGE("Failed to extract ssid");
    if (!(bssid = strsep(&next, "\t")))
        LOGE("Failed to extract bssid");
    if (!(flags = strsep(&next, "\t")))
        LOGE("Failed to extract flags");

   // LOGD("id '%s', ssid '%s', bssid '%s', flags '%s'", id, ssid, bssid,
   //      flags ? flags :"null");

    if (id)
        mNetid = atoi(id);
    if (ssid)
        mSsid = strdup(ssid);
    if (bssid)
        mBssid = strdup(bssid);

    mPsk = NULL;
    memset(mWepKeys, 0, sizeof(mWepKeys));
    mDefaultKeyIndex = -1;
    mPriority = -1;
    mHiddenSsid = NULL;
    mKeyManagement = KeyManagementMask::UNKNOWN;
    mProtocols = 0;
    mAuthAlgorithms = 0;
    mPairwiseCiphers = 0;
    mGroupCiphers = 0;
    mEnabled = true;

    if (flags && flags[0] != '\0') {
        if (!strcmp(flags, "[DISABLED]"))
            mEnabled = false;
        else
            LOGW("Unsupported flags '%s'", flags);
    }

    free(tmp);
    createProperties();
}

WifiNetwork::WifiNetwork(WifiController *c, Supplicant *suppl, int networkId) {
    mController = c;
    mSuppl = suppl;
    mNetid = networkId;
    mSsid = NULL;
    mBssid = NULL;
    mPsk = NULL;
    memset(mWepKeys, 0, sizeof(mWepKeys));
    mDefaultKeyIndex = -1;
    mPriority = -1;
    mHiddenSsid = NULL;
    mKeyManagement = 0;
    mProtocols = 0;
    mAuthAlgorithms = 0;
    mPairwiseCiphers = 0;
    mGroupCiphers = 0;
    mEnabled = false;
    createProperties();
}

WifiNetwork *WifiNetwork::clone() {
    WifiNetwork *r = new WifiNetwork();

    r->mSuppl = mSuppl;
    r->mNetid = mNetid;

    if (mSsid)
        r->mSsid = strdup(mSsid);
    if (mBssid)
        r->mBssid = strdup(mBssid);
    if (mPsk)
        r->mPsk = strdup(mPsk);

    r->mController = mController;
    memcpy(r->mWepKeys, mWepKeys, sizeof(mWepKeys));
    r->mDefaultKeyIndex = mDefaultKeyIndex;
    r->mPriority = mPriority;
    if (mHiddenSsid)
        r->mHiddenSsid = strdup(mHiddenSsid);
    r->mKeyManagement = mKeyManagement;
    r->mProtocols = mProtocols;
    r->mAuthAlgorithms = mAuthAlgorithms;
    r->mPairwiseCiphers = mPairwiseCiphers;
    r->mGroupCiphers = mGroupCiphers;
    return r;
}

void WifiNetwork::createProperties() {
    asprintf(&mPropNamespace, "wifi.net.%d", mNetid);

    mStaticProperties.propEnabled = new WifiNetworkEnabledProperty(this);
    mStaticProperties.propSsid = new WifiNetworkSsidProperty(this);
    mStaticProperties.propBssid = new WifiNetworkBssidProperty(this);
    mStaticProperties.propPsk = new WifiNetworkPskProperty(this);
    mStaticProperties.propWepKey = new WifiNetworkWepKeyProperty(this);
    mStaticProperties.propDefKeyIdx = new WifiNetworkDefaultKeyIndexProperty(this);
    mStaticProperties.propPriority = new WifiNetworkPriorityProperty(this);
    mStaticProperties.propKeyManagement = new WifiNetworkKeyManagementProperty(this);
    mStaticProperties.propProtocols = new WifiNetworkProtocolsProperty(this);
    mStaticProperties.propAuthAlgorithms = new WifiNetworkAuthAlgorithmsProperty(this);
    mStaticProperties.propPairwiseCiphers = new WifiNetworkPairwiseCiphersProperty(this);
    mStaticProperties.propGroupCiphers = new WifiNetworkGroupCiphersProperty(this);
    mStaticProperties.propHiddenSsid = new WifiNetworkHiddenSsidProperty(this);
}

WifiNetwork::~WifiNetwork() {
    if (mPropNamespace)
        free(mPropNamespace);
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

    delete mStaticProperties.propEnabled;
    delete mStaticProperties.propSsid;
    delete mStaticProperties.propBssid;
    delete mStaticProperties.propPsk;
    delete mStaticProperties.propWepKey;
    delete mStaticProperties.propDefKeyIdx;
    delete mStaticProperties.propPriority;
    delete mStaticProperties.propKeyManagement;
    delete mStaticProperties.propProtocols;
    delete mStaticProperties.propAuthAlgorithms;
    delete mStaticProperties.propPairwiseCiphers;
    delete mStaticProperties.propGroupCiphers;
    delete mStaticProperties.propHiddenSsid;
}

int WifiNetwork::refresh() {
    char buffer[255];
    size_t len;
    uint32_t mask;

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "psk", buffer, len))
        mPsk = strdup(buffer);

    for (int i = 0; i < 4; i++) {
        char *name;

        asprintf(&name, "wep_key%d", i);
        len = sizeof(buffer);
        if (mSuppl->getNetworkVar(mNetid, name, buffer, len))
            mWepKeys[i] = strdup(buffer);
        free(name);
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "wep_tx_keyidx", buffer, len))
        mDefaultKeyIndex = atoi(buffer);

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "priority", buffer, len))
        mPriority = atoi(buffer);

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "scan_ssid", buffer, len))
        mHiddenSsid = strdup(buffer);

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "key_mgmt", buffer, len)) {
        if (WifiNetwork::parseKeyManagementMask(buffer, &mask)) {
            LOGE("Error parsing key_mgmt (%s)", strerror(errno));
        } else {
           mKeyManagement = mask;
        }
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "proto", buffer, len)) {
        if (WifiNetwork::parseProtocolsMask(buffer, &mask)) {
            LOGE("Error parsing proto (%s)", strerror(errno));
        } else {
           mProtocols = mask;
        }
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "auth_alg", buffer, len)) {
        if (WifiNetwork::parseAuthAlgorithmsMask(buffer, &mask)) {
            LOGE("Error parsing auth_alg (%s)", strerror(errno));
        } else {
           mAuthAlgorithms = mask;
        }
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "pairwise", buffer, len)) {
        if (WifiNetwork::parsePairwiseCiphersMask(buffer, &mask)) {
            LOGE("Error parsing pairwise (%s)", strerror(errno));
        } else {
           mPairwiseCiphers = mask;
        }
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "group", buffer, len)) {
        if (WifiNetwork::parseGroupCiphersMask(buffer, &mask)) {
            LOGE("Error parsing group (%s)", strerror(errno));
        } else {
           mGroupCiphers = mask;
        }
    }

    return 0;
out_err:
    LOGE("Refresh failed (%s)",strerror(errno));
    return -1;
}

int WifiNetwork::setSsid(const char *ssid) {
    char tmp[255];
    snprintf(tmp, sizeof(tmp), "\"%s\"", ssid);
    if (mSuppl->setNetworkVar(mNetid, "ssid", tmp))
        return -1;
    if (mSsid)
        free(mSsid);
    mSsid = strdup(ssid);
    return 0;
}

int WifiNetwork::setBssid(const char *bssid) {
    if (mSuppl->setNetworkVar(mNetid, "bssid", bssid))
        return -1;
    if (mBssid)
        free(mBssid);
    mBssid = strdup(bssid);
    return 0;
}

int WifiNetwork::setPsk(const char *psk) {
    char tmp[255];
    snprintf(tmp, sizeof(tmp), "\"%s\"", psk);
    if (mSuppl->setNetworkVar(mNetid, "psk", tmp))
        return -1;

    if (mPsk)
        free(mPsk);
    mPsk = strdup(psk);
    return 0;
}

int WifiNetwork::setWepKey(int idx, const char *key) {
    char *name;

    asprintf(&name, "wep_key%d", idx);
    int rc = mSuppl->setNetworkVar(mNetid, name, key);
    free(name);

    if (rc)
        return -1;

    if (mWepKeys[idx])
        free(mWepKeys[idx]);
    mWepKeys[idx] = strdup(key);
    return 0;
}

int WifiNetwork::setDefaultKeyIndex(int idx) {
    char val[16];
    sprintf(val, "%d", idx);
    if (mSuppl->setNetworkVar(mNetid, "wep_tx_keyidx", val))
        return -1;

    mDefaultKeyIndex = idx;
    return 0;
}

int WifiNetwork::setPriority(int priority) {
    char val[16];
    sprintf(val, "%d", priority);
    if (mSuppl->setNetworkVar(mNetid, "priority", val))
        return -1;

    mPriority = priority;
    return 0;
}

int WifiNetwork::setHiddenSsid(const char *ssid) {
    if (mSuppl->setNetworkVar(mNetid, "scan_ssid", ssid))
        return -1;

    if (mHiddenSsid)
        free(mHiddenSsid);
    mHiddenSsid = strdup(ssid);
    return 0;
}

int WifiNetwork::setKeyManagement(uint32_t mask) {
    char accum[64] = {'\0'};

    if (mask == KeyManagementMask::NONE)
        strcpy(accum, "NONE");
    else {
        if (mask & KeyManagementMask::WPA_PSK) 
            strcat(accum, "WPA-PSK");
        if (mask & KeyManagementMask::WPA_EAP) {
            if (accum[0] != '\0')
                strcat(accum, " ");
            strcat(accum, "WPA-EAP");
        }
        if (mask & KeyManagementMask::IEEE8021X) {
            if (accum[0] != '\0')
                strcat(accum, " ");
            strcat(accum, "IEEE8021X");
        }
    }

    if (mSuppl->setNetworkVar(mNetid, "key_mgmt", accum))
        return -1;
    mKeyManagement = mask;
    return 0;
}

int WifiNetwork::setProtocols(uint32_t mask) {
    char accum[64];

    accum[0] = '\0';

    if (mask & SecurityProtocolMask::WPA)
        strcpy(accum, "WPA ");

    if (mask & SecurityProtocolMask::RSN)
        strcat(accum, "RSN");

    if (mSuppl->setNetworkVar(mNetid, "proto", accum))
        return -1;
    mProtocols = mask;
    return 0;
}

int WifiNetwork::setAuthAlgorithms(uint32_t mask) {
    char accum[64];

    accum[0] = '\0';

    if (mask == 0)
        strcpy(accum, "");

    if (mask & AuthenticationAlgorithmMask::OPEN)
        strcpy(accum, "OPEN ");

    if (mask & AuthenticationAlgorithmMask::SHARED)
        strcat(accum, "SHARED ");

    if (mask & AuthenticationAlgorithmMask::LEAP)
        strcat(accum, "LEAP ");

    if (mSuppl->setNetworkVar(mNetid, "auth_alg", accum))
        return -1;

    mAuthAlgorithms = mask;
    return 0;
}

int WifiNetwork::setPairwiseCiphers(uint32_t mask) {
    char accum[64];

    accum[0] = '\0';

    if (mask == PairwiseCiphersMask::NONE)
        strcpy(accum, "NONE");
    else {
        if (mask & PairwiseCiphersMask::TKIP)
            strcat(accum, "TKIP ");
        if (mask & PairwiseCiphersMask::CCMP)
            strcat(accum, "CCMP ");
    }

    if (mSuppl->setNetworkVar(mNetid, "pairwise", accum))
        return -1;

    mPairwiseCiphers = mask;
    return 0;
}

int WifiNetwork::setGroupCiphers(uint32_t mask) {
    char accum[64];

    accum[0] = '\0';

    if (mask & GroupCiphersMask::WEP40)
        strcat(accum, "WEP40 ");
    if (mask & GroupCiphersMask::WEP104)
        strcat(accum, "WEP104 ");
    if (mask & GroupCiphersMask::TKIP)
        strcat(accum, "TKIP ");
    if (mask & GroupCiphersMask::CCMP)
        strcat(accum, "CCMP ");

    if (mSuppl->setNetworkVar(mNetid, "group", accum))
        return -1;
    mGroupCiphers = mask;
    return 0;
}

int WifiNetwork::setEnabled(bool enabled) {

    if (enabled) {
        if (getPriority() == -1) {
            LOGE("Cannot enable network when priority is not set");
            errno = EAGAIN;
            return -1;
        }
        if (getKeyManagement() == KeyManagementMask::UNKNOWN) {
            LOGE("Cannot enable network when KeyManagement is not set");
            errno = EAGAIN;
            return -1;
        }
    }

    if (mSuppl->enableNetwork(mNetid, enabled))
        return -1;

    mEnabled = enabled;
    return 0;
}

int WifiNetwork::attachProperties(PropertyManager *pm, const char *nsName) {
    pm->attachProperty(nsName, mStaticProperties.propSsid);
    pm->attachProperty(nsName, mStaticProperties.propBssid);
    pm->attachProperty(nsName, mStaticProperties.propPsk);
    pm->attachProperty(nsName, mStaticProperties.propWepKey);
    pm->attachProperty(nsName, mStaticProperties.propDefKeyIdx);
    pm->attachProperty(nsName, mStaticProperties.propPriority);
    pm->attachProperty(nsName, mStaticProperties.propKeyManagement);
    pm->attachProperty(nsName, mStaticProperties.propProtocols);
    pm->attachProperty(nsName, mStaticProperties.propAuthAlgorithms);
    pm->attachProperty(nsName, mStaticProperties.propPairwiseCiphers);
    pm->attachProperty(nsName, mStaticProperties.propGroupCiphers);
    pm->attachProperty(nsName, mStaticProperties.propHiddenSsid);
    pm->attachProperty(nsName, mStaticProperties.propEnabled);
    return 0;
}

int WifiNetwork::detachProperties(PropertyManager *pm, const char *nsName) {
    pm->detachProperty(nsName, mStaticProperties.propEnabled);
    pm->detachProperty(nsName, mStaticProperties.propSsid);
    pm->detachProperty(nsName, mStaticProperties.propBssid);
    pm->detachProperty(nsName, mStaticProperties.propPsk);
    pm->detachProperty(nsName, mStaticProperties.propWepKey);
    pm->detachProperty(nsName, mStaticProperties.propDefKeyIdx);
    pm->detachProperty(nsName, mStaticProperties.propPriority);
    pm->detachProperty(nsName, mStaticProperties.propKeyManagement);
    pm->detachProperty(nsName, mStaticProperties.propProtocols);
    pm->detachProperty(nsName, mStaticProperties.propAuthAlgorithms);
    pm->detachProperty(nsName, mStaticProperties.propPairwiseCiphers);
    pm->detachProperty(nsName, mStaticProperties.propGroupCiphers);
    pm->detachProperty(nsName, mStaticProperties.propHiddenSsid);
    return 0;
}

int WifiNetwork::parseKeyManagementMask(const char *buffer, uint32_t *mask) {
    bool none = false;
    char *v_tmp = strdup(buffer);
    char *v_next = v_tmp;
    char *v_token;

//    LOGD("parseKeyManagementMask(%s)", buffer);
    *mask = 0;

    while((v_token = strsep(&v_next, " "))) {
        if (!strcasecmp(v_token, "NONE")) {
            *mask = KeyManagementMask::NONE;
            none = true;
        } else if (!none) {
            if (!strcasecmp(v_token, "WPA-PSK"))
                *mask |= KeyManagementMask::WPA_PSK;
            else if (!strcasecmp(v_token, "WPA-EAP"))
                *mask |= KeyManagementMask::WPA_EAP;
            else if (!strcasecmp(v_token, "IEEE8021X"))
                *mask |= KeyManagementMask::IEEE8021X;
            else {
                LOGW("Invalid KeyManagementMask value '%s'", v_token);
                errno = EINVAL;
                free(v_tmp);
                return -1;
            }
        } else {
            LOGW("KeyManagementMask value '%s' when NONE", v_token);
            errno = EINVAL;
            free(v_tmp);
            return -1;
        }
    }
    free(v_tmp);
    return 0;
}

int WifiNetwork::parseProtocolsMask(const char *buffer, uint32_t *mask) {
    bool none = false;
    char *v_tmp = strdup(buffer);
    char *v_next = v_tmp;
    char *v_token;

//    LOGD("parseProtocolsMask(%s)", buffer);
    *mask = 0;
    while((v_token = strsep(&v_next, " "))) {
        if (!strcasecmp(v_token, "WPA"))
            *mask |= SecurityProtocolMask::WPA;
        else if (!strcasecmp(v_token, "RSN"))
            *mask |= SecurityProtocolMask::RSN;
        else {
            LOGW("Invalid ProtocolsMask value '%s'", v_token);
            errno = EINVAL;
            free(v_tmp);
            return -1;
        }
    }

    free(v_tmp);
    return 0;
}

int WifiNetwork::parseAuthAlgorithmsMask(const char *buffer, uint32_t *mask) {
    bool none = false;
    char *v_tmp = strdup(buffer);
    char *v_next = v_tmp;
    char *v_token;

//    LOGD("parseAuthAlgorithmsMask(%s)", buffer);

    *mask = 0;
    if (buffer[0] == '\0')
        return 0;

    while((v_token = strsep(&v_next, " "))) {
        if (!strcasecmp(v_token, "OPEN"))
            *mask |= AuthenticationAlgorithmMask::OPEN;
        else if (!strcasecmp(v_token, "SHARED"))
            *mask |= AuthenticationAlgorithmMask::SHARED;
        else if (!strcasecmp(v_token, "LEAP"))
            *mask |= AuthenticationAlgorithmMask::LEAP;
        else {
            LOGW("Invalid AuthAlgorithmsMask value '%s'", v_token);
            errno = EINVAL;
            free(v_tmp);
            return -1;
        }
    }
    free(v_tmp);
    return 0;
}

int WifiNetwork::parsePairwiseCiphersMask(const char *buffer, uint32_t *mask) {
    bool none = false;
    char *v_tmp = strdup(buffer);
    char *v_next = v_tmp;
    char *v_token;

//    LOGD("parsePairwiseCiphersMask(%s)", buffer);

    *mask = 0;
    while((v_token = strsep(&v_next, " "))) {
        if (!strcasecmp(v_token, "NONE")) {
            *mask = PairwiseCiphersMask::NONE;
            none = true;
        } else if (!none) {
            if (!strcasecmp(v_token, "TKIP"))
                *mask |= PairwiseCiphersMask::TKIP;
            else if (!strcasecmp(v_token, "CCMP"))
                *mask |= PairwiseCiphersMask::CCMP;
        else {
                LOGW("PairwiseCiphersMask value '%s' when NONE", v_token);
                errno = EINVAL;
                free(v_tmp);
                return -1;
            }
        } else {
            LOGW("Invalid PairwiseCiphersMask value '%s'", v_token);
            errno = EINVAL;
            free(v_tmp);
            return -1;
        }
    }
    free(v_tmp);
    return 0;
}

int WifiNetwork::parseGroupCiphersMask(const char *buffer, uint32_t *mask) {
    bool none = false;
    char *v_tmp = strdup(buffer);
    char *v_next = v_tmp;
    char *v_token;

//    LOGD("parseGroupCiphersMask(%s)", buffer);

    *mask = 0;
    while((v_token = strsep(&v_next, " "))) {
        if (!strcasecmp(v_token, "WEP40"))
            *mask |= GroupCiphersMask::WEP40;
        else if (!strcasecmp(v_token, "WEP104"))
            *mask |= GroupCiphersMask::WEP104;
        else if (!strcasecmp(v_token, "TKIP"))
            *mask |= GroupCiphersMask::TKIP;
        else if (!strcasecmp(v_token, "CCMP"))
            *mask |= GroupCiphersMask::CCMP;
        else {
            LOGW("Invalid GroupCiphersMask value '%s'", v_token);
            errno = EINVAL;
            free(v_tmp);
            return -1;
        }
    }
    free(v_tmp);
    return 0;
}

WifiNetwork::WifiNetworkIntegerProperty::WifiNetworkIntegerProperty(WifiNetwork *wn,
                                                      const char *name,
                                                      bool ro,
                                                      int elements) :
             IntegerProperty(name, ro, elements) {
    mWn = wn;
}

WifiNetwork::WifiNetworkStringProperty::WifiNetworkStringProperty(WifiNetwork *wn,
                                                                  const char *name,
                                                              bool ro, int elements) :
             StringProperty(name, ro, elements) {
    mWn = wn;
}

WifiNetwork::WifiNetworkEnabledProperty::WifiNetworkEnabledProperty(WifiNetwork *wn) :
                WifiNetworkIntegerProperty(wn, "Enabled", false, 1) {
}

int WifiNetwork::WifiNetworkEnabledProperty::get(int idx, int *buffer) {
    *buffer = mWn->mEnabled;
    return 0;
}
int WifiNetwork::WifiNetworkEnabledProperty::set(int idx, int value) {
    return mWn->setEnabled(value == 1);
}

WifiNetwork::WifiNetworkSsidProperty::WifiNetworkSsidProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "Ssid", false, 1) {
}

int WifiNetwork::WifiNetworkSsidProperty::get(int idx, char *buffer, size_t max) {
    strncpy(buffer,
            mWn->getSsid() ? mWn->getSsid() : "none",
            max);
    return 0;
}
int WifiNetwork::WifiNetworkSsidProperty::set(int idx, const char *value) {
    return mWn->setSsid(value);
}

WifiNetwork::WifiNetworkBssidProperty::WifiNetworkBssidProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "Bssid", false, 1) {
}
int WifiNetwork::WifiNetworkBssidProperty::get(int idx, char *buffer, size_t max) {
    strncpy(buffer,
            mWn->getBssid() ? mWn->getBssid() : "none",
            max);
    return 0;
}
int WifiNetwork::WifiNetworkBssidProperty::set(int idx, const char *value) {
    return mWn->setBssid(value);
}

WifiNetwork::WifiNetworkPskProperty::WifiNetworkPskProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "Psk", false, 1) {
}
int WifiNetwork::WifiNetworkPskProperty::get(int idx, char *buffer, size_t max) {
    strncpy(buffer,
            mWn->getPsk() ? mWn->getPsk() : "none",
            max);
    return 0;
}
int WifiNetwork::WifiNetworkPskProperty::set(int idx, const char *value) {
    return mWn->setPsk(value);
}

WifiNetwork::WifiNetworkWepKeyProperty::WifiNetworkWepKeyProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "WepKey", false, 4) {
}

int WifiNetwork::WifiNetworkWepKeyProperty::get(int idx, char *buffer, size_t max) {
    const char *key = mWn->getWepKey(idx);

    strncpy(buffer, (key ? key : "none"), max);
    return 0;
}
int WifiNetwork::WifiNetworkWepKeyProperty::set(int idx, const char *value) {
    return mWn->setWepKey(idx, value);
}

WifiNetwork::WifiNetworkDefaultKeyIndexProperty::WifiNetworkDefaultKeyIndexProperty(WifiNetwork *wn) :
                WifiNetworkIntegerProperty(wn, "DefaultKeyIndex", false,  1) {
}
int WifiNetwork::WifiNetworkDefaultKeyIndexProperty::get(int idx, int *buffer) {
    *buffer = mWn->getDefaultKeyIndex();
    return 0;
}
int WifiNetwork::WifiNetworkDefaultKeyIndexProperty::set(int idx, int value) {
    return mWn->setDefaultKeyIndex(value);
}

WifiNetwork::WifiNetworkPriorityProperty::WifiNetworkPriorityProperty(WifiNetwork *wn) :
                WifiNetworkIntegerProperty(wn, "Priority", false, 1) {
}
int WifiNetwork::WifiNetworkPriorityProperty::get(int idx, int *buffer) {
    *buffer = mWn->getPriority();
    return 0;
}
int WifiNetwork::WifiNetworkPriorityProperty::set(int idx, int value) {
    return mWn->setPriority(value);
}

WifiNetwork::WifiNetworkKeyManagementProperty::WifiNetworkKeyManagementProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "KeyManagement", false, 1) {
}
int WifiNetwork::WifiNetworkKeyManagementProperty::get(int idx, char *buffer, size_t max) {

    if (mWn->getKeyManagement() == KeyManagementMask::NONE)
        strncpy(buffer, "NONE", max);
    else {
        char tmp[80] = { '\0' };

        if (mWn->getKeyManagement() & KeyManagementMask::WPA_PSK)
            strcat(tmp, "WPA-PSK");
        if (mWn->getKeyManagement() & KeyManagementMask::WPA_EAP) {
            if (tmp[0] != '\0')
                strcat(tmp, " ");
            strcat(tmp, "WPA-EAP");
        }
        if (mWn->getKeyManagement() & KeyManagementMask::IEEE8021X) {
            if (tmp[0] != '\0')
                strcat(tmp, " ");
            strcat(tmp, "IEEE8021X");
        }
        if (tmp[0] == '\0') {
            strncpy(buffer, "(internal error)", max);
            errno = ENOENT;
            return -1;
        }
        if (tmp[strlen(tmp)] == ' ')
            tmp[strlen(tmp)] = '\0';

        strncpy(buffer, tmp, max);
    }
    return 0;
}
int WifiNetwork::WifiNetworkKeyManagementProperty::set(int idx, const char *value) {
    uint32_t mask;
    if (mWn->parseKeyManagementMask(value, &mask))
        return -1;
    return mWn->setKeyManagement(mask);
}

WifiNetwork::WifiNetworkProtocolsProperty::WifiNetworkProtocolsProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "Protocols", false, 1) {
}
int WifiNetwork::WifiNetworkProtocolsProperty::get(int idx, char *buffer, size_t max) {
    char tmp[80] = { '\0' };

    if (mWn->getProtocols() & SecurityProtocolMask::WPA)
        strcat(tmp, "WPA");
    if (mWn->getProtocols() & SecurityProtocolMask::RSN) {
        if (tmp[0] != '\0')
            strcat(tmp, " ");
        strcat(tmp, "RSN");
    }

    if (tmp[0] == '\0') {
        strncpy(buffer, "(internal error)", max);
        errno = ENOENT;
        return NULL;
    }
    if (tmp[strlen(tmp)] == ' ')
        tmp[strlen(tmp)] = '\0';

    strncpy(buffer, tmp, max);
    return 0;
}
int WifiNetwork::WifiNetworkProtocolsProperty::set(int idx, const char *value) {
    uint32_t mask;
    if (mWn->parseProtocolsMask(value, &mask))
        return -1;
    return mWn->setProtocols(mask);
}

WifiNetwork::WifiNetworkAuthAlgorithmsProperty::WifiNetworkAuthAlgorithmsProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "AuthAlgorithms", false, 1) {
}
int WifiNetwork::WifiNetworkAuthAlgorithmsProperty::get(int idx, char *buffer, size_t max) {
    char tmp[80] = { '\0' };

    if (mWn->getAuthAlgorithms() == 0) {
        strncpy(buffer, "NONE", max);
        return 0;
    }

    if (mWn->getAuthAlgorithms() & AuthenticationAlgorithmMask::OPEN)
        strcat(tmp, "OPEN");
    if (mWn->getAuthAlgorithms() & AuthenticationAlgorithmMask::SHARED) {
        if (tmp[0] != '\0')
            strcat(tmp, " ");
        strcat(tmp, "SHARED");
    }
    if (mWn->getAuthAlgorithms() & AuthenticationAlgorithmMask::LEAP) {
        if (tmp[0] != '\0')
            strcat(tmp, " ");
        strcat(tmp, "LEAP");
    }

    if (tmp[0] == '\0') {
        strncpy(buffer, "(internal error)", max);
        errno = ENOENT;
        return NULL;
    }
    if (tmp[strlen(tmp)] == ' ')
        tmp[strlen(tmp)] = '\0';

    strncpy(buffer, tmp, max);
    return 0;
}
int WifiNetwork::WifiNetworkAuthAlgorithmsProperty::set(int idx, const char *value) {
    uint32_t mask;
    if (mWn->parseAuthAlgorithmsMask(value, &mask))
        return -1;
    return mWn->setAuthAlgorithms(mask);
}

WifiNetwork::WifiNetworkPairwiseCiphersProperty::WifiNetworkPairwiseCiphersProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "PairwiseCiphers", false, 1) {
}
int WifiNetwork::WifiNetworkPairwiseCiphersProperty::get(int idx, char *buffer, size_t max) {
    if (mWn->getPairwiseCiphers() == PairwiseCiphersMask::NONE)
        strncpy(buffer, "NONE", max);
    else {
        char tmp[80] = { '\0' };

        if (mWn->getPairwiseCiphers() & PairwiseCiphersMask::TKIP)
            strcat(tmp, "TKIP");
        if (mWn->getPairwiseCiphers() & PairwiseCiphersMask::CCMP) {
            if (tmp[0] != '\0')
                strcat(tmp, " ");
            strcat(tmp, "CCMP");
        }
        if (tmp[0] == '\0') {
            strncpy(buffer, "(internal error)", max);
            errno = ENOENT;
            return NULL;
        }
        if (tmp[strlen(tmp)] == ' ')
            tmp[strlen(tmp)] = '\0';

        strncpy(buffer, tmp, max);
    }
    return 0;
}
int WifiNetwork::WifiNetworkPairwiseCiphersProperty::set(int idx, const char *value) {
    uint32_t mask;
    if (mWn->parsePairwiseCiphersMask(value, &mask))
        return -1;
    return mWn->setPairwiseCiphers(mask);
}

WifiNetwork::WifiNetworkGroupCiphersProperty::WifiNetworkGroupCiphersProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "GroupCiphers", false, 1) {
}
int WifiNetwork::WifiNetworkGroupCiphersProperty::get(int idx, char *buffer, size_t max) {
   char tmp[80] = { '\0' };

    if (mWn->getGroupCiphers() & GroupCiphersMask::WEP40)
        strcat(tmp, "WEP40");
    if (mWn->getGroupCiphers() & GroupCiphersMask::WEP104) {
        if (tmp[0] != '\0')
            strcat(tmp, " ");
        strcat(tmp, "WEP104");
    }
    if (mWn->getGroupCiphers() & GroupCiphersMask::TKIP) {
        if (tmp[0] != '\0')
            strcat(tmp, " ");
        strcat(tmp, "TKIP");
    }
    if (mWn->getGroupCiphers() & GroupCiphersMask::CCMP) {
        if (tmp[0] != '\0')
            strcat(tmp, " ");
        strcat(tmp, "CCMP");
    }

    if (tmp[0] == '\0') {
        strncpy(buffer, "(internal error)", max);
        errno = ENOENT;
        return -1;
    }
    if (tmp[strlen(tmp)] == ' ')
        tmp[strlen(tmp)] = '\0';

    strncpy(buffer, tmp, max);
    return 0;
}
int WifiNetwork::WifiNetworkGroupCiphersProperty::set(int idx, const char *value) {
    uint32_t mask;
    if (mWn->parseGroupCiphersMask(value, &mask))
        return -1;
    return mWn->setGroupCiphers(mask);
}

WifiNetwork::WifiNetworkHiddenSsidProperty::WifiNetworkHiddenSsidProperty(WifiNetwork *wn) :
                WifiNetworkStringProperty(wn, "HiddenSsid", false, 1) {
}
int WifiNetwork::WifiNetworkHiddenSsidProperty::get(int idx, char *buffer, size_t max) {
    const char *scan_ssid = mWn->getHiddenSsid();
    
    strncpy(buffer, (scan_ssid ? scan_ssid : "none"), max);
    return 0;
}
int WifiNetwork::WifiNetworkHiddenSsidProperty::set(int idx, const char *value) {
    return mWn->setHiddenSsid(value);
}
