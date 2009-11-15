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

#ifndef _WIFI_NETWORK_H
#define _WIFI_NETWORK_H

#include <sys/types.h>

#include <utils/List.h>

#include "Property.h"

class PropertyManager;

class KeyManagementMask {
public:
    static const uint32_t UNKNOWN   = 0;
    static const uint32_t NONE      = 0x01;
    static const uint32_t WPA_PSK   = 0x02;
    static const uint32_t WPA_EAP   = 0x04;
    static const uint32_t IEEE8021X = 0x08;
    static const uint32_t ALL       = WPA_PSK | WPA_EAP | IEEE8021X;
};

class SecurityProtocolMask {
public:
    static const uint32_t WPA = 0x01;
    static const uint32_t RSN = 0x02;
};

class AuthenticationAlgorithmMask {
public:
    static const uint32_t OPEN   = 0x01;
    static const uint32_t SHARED = 0x02;
    static const uint32_t LEAP   = 0x04;
};

class PairwiseCiphersMask {
public:
    static const uint32_t NONE = 0x00;
    static const uint32_t TKIP = 0x01;
    static const uint32_t CCMP = 0x02;
};

class GroupCiphersMask {
public:
    static const uint32_t WEP40  = 0x01;
    static const uint32_t WEP104 = 0x02;
    static const uint32_t TKIP   = 0x04;
    static const uint32_t CCMP   = 0x08;
};

class Supplicant;
class Controller;
class WifiController;

class WifiNetwork {
    class WifiNetworkIntegerProperty : public IntegerProperty {
    protected:
        WifiNetwork *mWn;
    public:
        WifiNetworkIntegerProperty(WifiNetwork *wn, const char *name, bool ro,
                                   int elements);
        virtual ~WifiNetworkIntegerProperty() {}
        virtual int set(int idx, int value) = 0;
        virtual int get(int idx, int *buffer) = 0;
    };
    friend class WifiNetwork::WifiNetworkIntegerProperty;

    class WifiNetworkStringProperty : public StringProperty {
    protected:
        WifiNetwork *mWn;
    public:
        WifiNetworkStringProperty(WifiNetwork *wn, const char *name, bool ro,
                                 int elements);
        virtual ~WifiNetworkStringProperty() {}
        virtual int set(int idx, const char *value) = 0;
        virtual int get(int idx, char *buffer, size_t max) = 0;
    };
    friend class WifiNetwork::WifiNetworkStringProperty;

    class WifiNetworkEnabledProperty : public WifiNetworkIntegerProperty {
    public:
        WifiNetworkEnabledProperty(WifiNetwork *wn);
        virtual ~WifiNetworkEnabledProperty() {};
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiNetworkPriorityProperty : public WifiNetworkIntegerProperty {
    public:
        WifiNetworkPriorityProperty(WifiNetwork *wn);
        virtual ~WifiNetworkPriorityProperty() {};
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiNetworkDefaultKeyIndexProperty : public WifiNetworkIntegerProperty {
    public:
        WifiNetworkDefaultKeyIndexProperty(WifiNetwork *wn);
        virtual ~WifiNetworkDefaultKeyIndexProperty() {};
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    class WifiNetworkSsidProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkSsidProperty(WifiNetwork *wn);
        virtual ~WifiNetworkSsidProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkBssidProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkBssidProperty(WifiNetwork *wn);
        virtual ~WifiNetworkBssidProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkPskProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkPskProperty(WifiNetwork *wn);
        virtual ~WifiNetworkPskProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkKeyManagementProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkKeyManagementProperty(WifiNetwork *wn);
        virtual ~WifiNetworkKeyManagementProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkAuthAlgorithmsProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkAuthAlgorithmsProperty(WifiNetwork *wn);
        virtual ~WifiNetworkAuthAlgorithmsProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkProtocolsProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkProtocolsProperty(WifiNetwork *wn);
        virtual ~WifiNetworkProtocolsProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkWepKeyProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkWepKeyProperty(WifiNetwork *wn);
        virtual ~WifiNetworkWepKeyProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkPairwiseCiphersProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkPairwiseCiphersProperty(WifiNetwork *wn);
        virtual ~WifiNetworkPairwiseCiphersProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkGroupCiphersProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkGroupCiphersProperty(WifiNetwork *wn);
        virtual ~WifiNetworkGroupCiphersProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

    class WifiNetworkHiddenSsidProperty : public WifiNetworkStringProperty {
    public:
        WifiNetworkHiddenSsidProperty(WifiNetwork *wn);
        virtual ~WifiNetworkHiddenSsidProperty() {};
        int set(int idx, const char *value);
        int get(int idx, char *buffer, size_t max);
    };

private:
    Supplicant *mSuppl;
    WifiController *mController;

    /*
     * Unique network id - normally provided by supplicant
     */
    int mNetid;

    /*
     * The networks' SSID. Can either be an ASCII string,
     * which must be enclosed in double quotation marks
     * (ie: "MyNetwork"), or a string of hex digits which
     * are not enclosed in quotes (ie: 01ab7893)
     */
    char *mSsid;

    /*
     * When set, this entry should only be used
     * when associating with the AP having the specified
     * BSSID. The value is a string in the format of an
     * Ethernet MAC address
     */
    char *mBssid;

    /*
     *  Pre-shared key for use with WPA-PSK
     */
    char *mPsk;

    /*
     * Up to four WEP keys. Either in ASCII string enclosed in
     * double quotes, or a string of hex digits
     */
    char *mWepKeys[4];

    /*
     * Default WEP key index, ranging from 0 -> NUM_WEP_KEYS -1
     */
    int mDefaultKeyIndex;

    /*
     * Priority determines the preference given to a network by 
     * supplicant when choosing an access point with which
     * to associate
     */
    int mPriority;

    /*
     * This is a network that does not broadcast it's SSID, so an
     * SSID-specific probe request must be used for scans.
     */
    char *mHiddenSsid;

    /*
     * The set of key management protocols supported by this configuration.
     */
    uint32_t mKeyManagement;

    /*
     * The set of security protocols supported by this configuration.
     */
    uint32_t mProtocols;

    /*
     * The set of authentication protocols supported by this configuration.
     */
    uint32_t mAuthAlgorithms;

    /*
     * The set of pairwise ciphers for WPA supported by this configuration.
     */
    uint32_t mPairwiseCiphers;

    /*
     * The set of group ciphers for WPA supported by this configuration.
     */
    uint32_t mGroupCiphers;

    /*
     * Set if this Network is enabled
     */
    bool mEnabled;

    char *mPropNamespace;
    struct {
        WifiNetworkEnabledProperty               *propEnabled;
        WifiNetworkSsidProperty                  *propSsid;
        WifiNetworkBssidProperty                 *propBssid;
        WifiNetworkPskProperty                   *propPsk;
        WifiNetworkWepKeyProperty                *propWepKey;
        WifiNetworkDefaultKeyIndexProperty       *propDefKeyIdx;
        WifiNetworkPriorityProperty              *propPriority;
        WifiNetworkKeyManagementProperty  *propKeyManagement;
        WifiNetworkProtocolsProperty      *propProtocols;
        WifiNetworkAuthAlgorithmsProperty *propAuthAlgorithms;
        WifiNetworkPairwiseCiphersProperty       *propPairwiseCiphers;
        WifiNetworkGroupCiphersProperty          *propGroupCiphers;
        WifiNetworkHiddenSsidProperty            *propHiddenSsid;
    } mStaticProperties;
private:
    WifiNetwork();

public:
    WifiNetwork(WifiController *c, Supplicant *suppl, int networkId);
    WifiNetwork(WifiController *c, Supplicant *suppl, const char *data);

    virtual ~WifiNetwork();

    WifiNetwork *clone();
    int attachProperties(PropertyManager *pm, const char *nsName);
    int detachProperties(PropertyManager *pm, const char *nsName);

    int getNetworkId() { return mNetid; }
    const char *getSsid() { return mSsid; }
    const char *getBssid() { return mBssid; }
    const char *getPsk() { return mPsk; }
    const char *getWepKey(int idx) { return mWepKeys[idx]; }
    int getDefaultKeyIndex() { return mDefaultKeyIndex; }
    int getPriority() { return mPriority; }
    const char *getHiddenSsid() { return mHiddenSsid; }
    uint32_t getKeyManagement() { return mKeyManagement; }
    uint32_t getProtocols() { return mProtocols; }
    uint32_t getAuthAlgorithms() { return mAuthAlgorithms; }
    uint32_t getPairwiseCiphers() { return mPairwiseCiphers; }
    uint32_t getGroupCiphers() { return mGroupCiphers; }
    bool getEnabled() { return mEnabled; }
    Controller *getController() { return (Controller *) mController; }

    int setEnabled(bool enabled);
    int setSsid(const char *ssid);
    int setBssid(const char *bssid);
    int setPsk(const char *psk);
    int setWepKey(int idx, const char *key);
    int setDefaultKeyIndex(int idx);
    int setPriority(int pri);
    int setHiddenSsid(const char *ssid);
    int setKeyManagement(uint32_t mask);
    int setProtocols(uint32_t mask);
    int setAuthAlgorithms(uint32_t mask);
    int setPairwiseCiphers(uint32_t mask);
    int setGroupCiphers(uint32_t mask);

    // XXX:Should this really be exposed?.. meh
    int refresh();

private:
    int parseKeyManagementMask(const char *buffer, uint32_t *mask);
    int parseProtocolsMask(const char *buffer, uint32_t *mask);
    int parseAuthAlgorithmsMask(const char *buffer, uint32_t *mask);
    int parsePairwiseCiphersMask(const char *buffer, uint32_t *mask);
    int parseGroupCiphersMask(const char *buffer, uint32_t *mask);
    void createProperties();
};

typedef android::List<WifiNetwork *> WifiNetworkCollection;

#endif
