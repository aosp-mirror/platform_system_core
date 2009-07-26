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
#include "InterfaceConfig.h"

const char *WifiNetwork::PropertyNames[] = { "ssid", "bssid", "psk", "wepkey.1",
                                             "wepkey.2", "wepkey.3", "wepkey.4",
                                             "defkeyidx", "pri", "hiddenssid",
                                             "AllowedKeyManagement",
                                             "AllowedProtocols",
                                             "AllowedAuthAlgorithms",
                                             "AllowedPairwiseCiphers",
                                             "AllowedGroupCiphers",
                                             "enabled", '\0' };
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
    mAllowedKeyManagement = KeyManagementMask::UNKNOWN;
    mAllowedProtocols = 0;
    mAllowedAuthAlgorithms = 0;
    mAllowedPairwiseCiphers = 0;
    mAllowedGroupCiphers = 0;
    mEnabled = true;

    if (flags && flags[0] != '\0') {
        if (!strcmp(flags, "[DISABLED]"))
            mEnabled = false;
        else
            LOGW("Unsupported flags '%s'", flags);
    }

    char *tmp2;
    asprintf(&tmp2, "wifi.net.%d", mNetid);
    mIfaceCfg = new InterfaceConfig(tmp2);
    free(tmp2);
    free(tmp);
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
    mAllowedKeyManagement = 0;
    mAllowedProtocols = 0;
    mAllowedAuthAlgorithms = 0;
    mAllowedPairwiseCiphers = 0;
    mAllowedGroupCiphers = 0;
    mEnabled = false;

    char *tmp2;
    asprintf(&tmp2, "wifi.net.%d", mNetid);
    mIfaceCfg = new InterfaceConfig(tmp2);
    free(tmp2);
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
    r->mAllowedKeyManagement = mAllowedKeyManagement;
    r->mAllowedProtocols = mAllowedProtocols;
    r->mAllowedAuthAlgorithms = mAllowedAuthAlgorithms;
    r->mAllowedPairwiseCiphers = mAllowedPairwiseCiphers;
    r->mAllowedGroupCiphers = mAllowedGroupCiphers;
    return r;
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
    if (mIfaceCfg)
        delete(mIfaceCfg);
}

int WifiNetwork::refresh() {
    char buffer[255];
    size_t len;

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
        if (!strcmp(buffer, "NONE"))
            setAllowedKeyManagement(KeyManagementMask::NONE);
        else if (index(buffer, ' ')) {
            char *next = buffer;
            char *token;
            uint32_t mask = 0;

            while((token = strsep(&next, " "))) {
                if (!strcmp(token, "WPA-PSK"))
                    mask |= KeyManagementMask::WPA_PSK;
                else if (!strcmp(token, "WPA-EAP"))
                    mask |= KeyManagementMask::WPA_EAP;
                else if (!strcmp(token, "IEE8021X"))
                    mask |= KeyManagementMask::IEEE8021X;
                else
                    LOGW("Unsupported key management scheme '%s'" , token);
            }
            setAllowedKeyManagement(mask);
        } else
            LOGE("Unsupported key management '%s'", buffer);
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "proto", buffer, len)) {
        // TODO
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "auth_alg", buffer, len)) {
        // TODO
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "pairwise", buffer, len)) {
        // TODO
    }

    len = sizeof(buffer);
    if (mSuppl->getNetworkVar(mNetid, "group", buffer, len)) {
        // TODO
    }

    return 0;
out_err:
    LOGE("Refresh failed (%s)",strerror(errno));
    return -1;
}

int WifiNetwork::set(const char *name, const char *value) {
    char *n_tmp = strdup(name + strlen("wifi.net."));
    char *n_next = n_tmp;
    char *n_local;
    char *n_rest;
    int rc = 0;

    if (!strsep(&n_next, ".")) // skip net id
        goto out_inval;

    if (!(n_local = strsep(&n_next, ".")))
        goto out_inval;

    n_rest = n_next;

//    LOGD("set(): var '%s'(%s / %s) = %s", name, n_local, n_rest, value);
    if (!strcasecmp(n_local, "enabled"))
        rc = setEnabled(atoi(value));
    else if (!strcmp(n_local, "ssid"))
        rc = setSsid(value);
    else if (!strcasecmp(n_local, "bssid"))
        rc = setBssid(value);
    else if (!strcasecmp(n_local, "psk"))
        rc = setPsk(value);
    else if (!strcasecmp(n_local, "wepkey"))
        rc = setWepKey(atoi(n_rest) -1, value);
    else if (!strcasecmp(n_local, "defkeyidx"))
        rc = setDefaultKeyIndex(atoi(value));
    else if (!strcasecmp(n_local, "pri"))
        rc = setPriority(atoi(value));
    else if (!strcasecmp(n_local, "hiddenssid"))
        rc = setHiddenSsid(value);
    else if (!strcasecmp(n_local, "AllowedKeyManagement")) {
        uint32_t mask = 0;
        bool none = false;
        char *v_tmp = strdup(value);
        char *v_next = v_tmp;
        char *v_token;

        while((v_token = strsep(&v_next, " "))) {
            if (!strcasecmp(v_token, "NONE")) {
                mask = KeyManagementMask::NONE;
                none = true;
            } else if (!none) {
                if (!strcasecmp(v_token, "WPA_PSK"))
                    mask |= KeyManagementMask::WPA_PSK;
                else if (!strcasecmp(v_token, "WPA_EAP"))
                    mask |= KeyManagementMask::WPA_EAP;
                else if (!strcasecmp(v_token, "IEEE8021X"))
                    mask |= KeyManagementMask::IEEE8021X;
                else {
                    errno = EINVAL;
                    rc = -1;
                    free(v_tmp);
                    goto out;
                }
            } else {
                errno = EINVAL;
                rc = -1;
                free(v_tmp);
                goto out;
            }
        }
        free(v_tmp);
    } else if (!strcasecmp(n_local, "AllowedProtocols")) {
        // TODO
    } else if (!strcasecmp(n_local, "AllowedPairwiseCiphers")) {
        // TODO
    } else if (!strcasecmp(n_local, "AllowedAuthAlgorithms")) {
        // TODO
    } else if (!strcasecmp(n_local, "AllowedGroupCiphers")) {
        // TODO
    } else {
        errno = ENOENT;
        free(n_tmp);
        return -1;
    }

out:
    free(n_tmp);
    return rc;

out_inval:
    errno = EINVAL;
    free(n_tmp);
    return -1;
}

const char *WifiNetwork::get(const char *name, char *buffer, size_t maxsize) {
    char *n_tmp = strdup(name + strlen("wifi.net."));
    char *n_next = n_tmp;
    char *n_local;
    char fc[64];
    char rc[128];

    if (!strsep(&n_next, ".")) // skip net id
        goto out_inval;

    if (!(n_local = strsep(&n_next, ".")))
        goto out_inval;


    strncpy(fc, n_local, sizeof(fc));
    rc[0] = '\0';
    if (n_next)
        strncpy(rc, n_next, sizeof(rc));

    free(n_tmp);

    if (!strcasecmp(fc, "enabled"))
        snprintf(buffer, maxsize, "%d", getEnabled());
    else if (!strcasecmp(fc, "ssid")) {
        strncpy(buffer,
                getSsid() ? getSsid() : "none",
                maxsize);
    } else if (!strcasecmp(fc, "bssid")) {
        strncpy(buffer,
                getBssid() ? getBssid() : "none",
                maxsize);
    } else if (!strcasecmp(fc, "psk")) {
        strncpy(buffer,
                getPsk() ? getPsk() : "none",
                maxsize);
    } else if (!strcasecmp(fc, "wepkey")) {
        strncpy(buffer,
                getWepKey(atoi(rc)-1) ? getWepKey(atoi(rc)-1) : "none",
                maxsize);
    } else if (!strcasecmp(fc, "defkeyidx"))
        snprintf(buffer, maxsize, "%d", getDefaultKeyIndex());
    else if (!strcasecmp(fc, "pri"))
        snprintf(buffer, maxsize, "%d", getPriority());
    else if (!strcasecmp(fc, "AllowedKeyManagement")) {
        if (getAllowedKeyManagement() == KeyManagementMask::NONE) 
            strncpy(buffer, "NONE", maxsize);
        else {
            char tmp[80] = { '\0' };

            if (getAllowedKeyManagement() & KeyManagementMask::WPA_PSK)
                strcat(tmp, "WPA_PSK ");
            if (getAllowedKeyManagement() & KeyManagementMask::WPA_EAP)
                strcat(tmp, "WPA_EAP ");
            if (getAllowedKeyManagement() & KeyManagementMask::IEEE8021X)
                strcat(tmp, "IEEE8021X");
            if (tmp[0] == '\0') {
                strncpy(buffer, "(internal error)", maxsize);
                errno = ENOENT;
                return NULL;
            }
            if (tmp[strlen(tmp)] == ' ')
                tmp[strlen(tmp)] = '\0';

            strncpy(buffer, tmp, maxsize);
        }
    } else if (!strcasecmp(fc, "hiddenssid")) {
        strncpy(buffer,
                getHiddenSsid() ? getHiddenSsid() : "none",
                maxsize);
    } else {
        strncpy(buffer, "(internal error)", maxsize);
        errno = ENOENT;
        return NULL;
    }

    return buffer;

out_inval:
    errno = EINVAL;
    free(n_tmp);
    return NULL;
}

int WifiNetwork::setSsid(const char *ssid) {
    if (mSuppl->setNetworkVar(mNetid, "ssid", ssid))
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
    if (mSuppl->setNetworkVar(mNetid, "psk", psk))
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

int WifiNetwork::setAllowedKeyManagement(uint32_t mask) {
    char accum[255];

    if (mask == KeyManagementMask::NONE)
        strcpy(accum, "NONE");
    else {
        if (mask & KeyManagementMask::WPA_PSK)
            strcat(accum, "WPA_PSK ");
        if (mask & KeyManagementMask::WPA_EAP)
            strcat(accum, "WPA_EAP ");
        if (mask & KeyManagementMask::IEEE8021X)
            strcat(accum, "IEEE8021X ");
    }

    if (mSuppl->setNetworkVar(mNetid, "key_mgmt", accum))
        return -1;
    mAllowedKeyManagement = mask;
    return 0;
}

int WifiNetwork::setAllowedProtocols(uint32_t mask) {
    char accum[255];

    accum[0] = '\0';

    if (mask & SecurityProtocolMask::WPA)
        strcpy(accum, "WPA ");

    if (mask & SecurityProtocolMask::RSN)
        strcat(accum, "RSN");

    if (mSuppl->setNetworkVar(mNetid, "proto", accum))
        return -1;
    mAllowedProtocols = mask;
    return 0;
}

int WifiNetwork::setAllowedAuthAlgorithms(uint32_t mask) {
    char accum[255];

    accum[0] = '\0';

    if (mask & AuthenticationAlgorithmMask::OPEN)
        strcpy(accum, "OPEN ");

    if (mask & AuthenticationAlgorithmMask::SHARED)
        strcat(accum, "SHARED ");

    if (mask & AuthenticationAlgorithmMask::LEAP)
        strcat(accum, "LEAP ");

    if (mSuppl->setNetworkVar(mNetid, "auth_alg", accum))
        return -1;

    mAllowedAuthAlgorithms = mask;
    return 0;
}

int WifiNetwork::setAllowedPairwiseCiphers(uint32_t mask) {
    char accum[255];

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

    mAllowedPairwiseCiphers = mask;
    return 0;
}

int WifiNetwork::setAllowedGroupCiphers(uint32_t mask) {
    char accum[255];

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
    mAllowedGroupCiphers = mask;
    return 0;
}

int WifiNetwork::setEnabled(bool enabled) {

    if (enabled) {
        if (getPriority() == -1) {
            LOGE("Cannot enable network when priority is not set");
            errno = EAGAIN;
            return -1;
        }
        if (getAllowedKeyManagement() == KeyManagementMask::UNKNOWN) {
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

int WifiNetwork::registerProperties() {
    for (const char **p = WifiNetwork::PropertyNames; *p != '\0'; p++) {
        char *tmp;
        asprintf(&tmp, "wifi.net.%d.%s", mNetid, *p);

        if (NetworkManager::Instance()->getPropMngr()->registerProperty(tmp,
                                                                        this)) {
            free(tmp);
            return -1;
        }
        free(tmp);
    }
    return 0;
}

int WifiNetwork::unregisterProperties() {
    for (const char **p = WifiNetwork::PropertyNames; *p != '\0'; p++) {
        char *tmp;
        asprintf(&tmp, "wifi.net.%d.%s", mNetid, *p);

        if (NetworkManager::Instance()->getPropMngr()->unregisterProperty(tmp))
            LOGW("Unable to remove property '%s' (%s)", tmp, strerror(errno));
        free(tmp);
    }
    return 0;
}
