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

#define LOG_TAG "InterfaceConfig"
#include <cutils/log.h>

#include "InterfaceConfig.h"
#include "NetworkManager.h"

InterfaceConfig::InterfaceConfig(bool propertiesReadOnly) {
    mStaticProperties.propIp = new IPV4AddressPropertyHelper("Addr", propertiesReadOnly, &mIp);
    mStaticProperties.propNetmask = new IPV4AddressPropertyHelper("Netmask", propertiesReadOnly, &mNetmask);
    mStaticProperties.propGateway = new IPV4AddressPropertyHelper("Gateway", propertiesReadOnly, &mGateway);
    mStaticProperties.propBroadcast = new IPV4AddressPropertyHelper("Broadcast", propertiesReadOnly, &mBroadcast);
    mStaticProperties.propDns = new InterfaceDnsProperty(this, propertiesReadOnly);
}

InterfaceConfig::~InterfaceConfig() {
    delete mStaticProperties.propIp;
    delete mStaticProperties.propNetmask;
    delete mStaticProperties.propGateway;
    delete mStaticProperties.propBroadcast;
    delete mStaticProperties.propDns;
}

void InterfaceConfig::setIp(struct in_addr *addr) {
    memcpy(&mIp, addr, sizeof(struct in_addr));
}

void InterfaceConfig::setNetmask(struct in_addr *addr) {
    memcpy(&mNetmask, addr, sizeof(struct in_addr));
}

void InterfaceConfig::setGateway(struct in_addr *addr) {
    memcpy(&mGateway, addr, sizeof(struct in_addr));
}

void InterfaceConfig::setBroadcast(struct in_addr *addr) {
    memcpy(&mBroadcast, addr, sizeof(struct in_addr));
}

void InterfaceConfig::setDns(int idx, struct in_addr *addr) {
    memcpy(&mDns[idx], addr, sizeof(struct in_addr));
}

int InterfaceConfig::attachProperties(PropertyManager *pm, const char *nsName) {
    pm->attachProperty(nsName, mStaticProperties.propIp);
    pm->attachProperty(nsName, mStaticProperties.propNetmask);
    pm->attachProperty(nsName, mStaticProperties.propGateway);
    pm->attachProperty(nsName, mStaticProperties.propBroadcast);
    pm->attachProperty(nsName, mStaticProperties.propDns);
    return 0;
}

int InterfaceConfig::detachProperties(PropertyManager *pm, const char *nsName) {
    pm->detachProperty(nsName, mStaticProperties.propIp);
    pm->detachProperty(nsName, mStaticProperties.propNetmask);
    pm->detachProperty(nsName, mStaticProperties.propGateway);
    pm->detachProperty(nsName, mStaticProperties.propBroadcast);
    pm->detachProperty(nsName, mStaticProperties.propDns);
    return 0;
}

InterfaceConfig::InterfaceDnsProperty::InterfaceDnsProperty(InterfaceConfig *c,
                                                            bool ro) :
                 IPV4AddressProperty("Dns", ro, 2) {
    mCfg = c;
}

int InterfaceConfig::InterfaceDnsProperty::set(int idx, struct in_addr *value) {
    memcpy(&mCfg->mDns[idx], value, sizeof(struct in_addr));
    return 0;
}
int InterfaceConfig::InterfaceDnsProperty::get(int idx, struct in_addr *buf) {
    memcpy(buf, &mCfg->mDns[idx], sizeof(struct in_addr));
    return 0;
}

