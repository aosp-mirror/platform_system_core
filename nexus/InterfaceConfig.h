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

#ifndef _INTERFACE_CONFIG_H
#define _INTERFACE_CONFIG_H

#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "Property.h"
class PropertyManager;

class InterfaceConfig {
    class InterfaceDnsProperty;
    friend class InterfaceConfig::InterfaceDnsProperty;

    struct {
        IPV4AddressPropertyHelper *propIp;
        IPV4AddressPropertyHelper *propNetmask;
        IPV4AddressPropertyHelper *propGateway;
        IPV4AddressPropertyHelper *propBroadcast;
        InterfaceDnsProperty      *propDns;
    } mStaticProperties;

    struct in_addr mIp;
    struct in_addr mNetmask;
    struct in_addr mGateway;
    struct in_addr mBroadcast;
    struct in_addr mDns[2];

public:
    InterfaceConfig(bool propertiesReadOnly);
    virtual ~InterfaceConfig();
    
    int set(const char *name, const char *value);
    const char *get(const char *name, char *buffer, size_t maxsize);

    const struct in_addr &getIp() const { return mIp; }
    const struct in_addr &getNetmask() const { return mNetmask; }
    const struct in_addr &getGateway() const { return mGateway; }
    const struct in_addr &getBroadcast() const { return mBroadcast; }
    const struct in_addr &getDns(int idx) const { return mDns[idx]; }

    void setIp(struct in_addr *addr);
    void setNetmask(struct in_addr *addr);
    void setGateway(struct in_addr *addr);
    void setBroadcast(struct in_addr *addr);
    void setDns(int idx, struct in_addr *addr);

    int attachProperties(PropertyManager *pm, const char *nsName);
    int detachProperties(PropertyManager *pm, const char *nsName);

private:

    class InterfaceDnsProperty : public IPV4AddressProperty {
        InterfaceConfig *mCfg;
    public:
        InterfaceDnsProperty(InterfaceConfig *cfg, bool ro);
        int set(int idx, struct in_addr *value);
        int get(int idx, struct in_addr *buffer);
    };
};


#endif
