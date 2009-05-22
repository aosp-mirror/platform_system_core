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

#include <netinet/in.h>
#include <arpa/inet.h>

class InterfaceConfig {
private:
    char *mName;
    bool mUseDhcp;
    struct in_addr mIp;
    struct in_addr mNetmask;
    struct in_addr mGateway;
    struct in_addr mDns1;
    struct in_addr mDns2;
    struct in_addr mDns3;

public:
    InterfaceConfig(const char *name);
    InterfaceConfig(const char *name, const char *ip, const char *nm,
                    const char *gw, const char *dns1, const char *dns2,
                    const char *dns3);

    InterfaceConfig(const char *name, const struct in_addr *ip,
                    const struct in_addr *nm, const struct in_addr *gw,
                    const struct in_addr *dns1, const struct in_addr *dns2,
                    const struct in_addr *dns3);

    virtual ~InterfaceConfig();

    const char     *getName() const { return mName; }
    bool            getUseDhcp() const { return mUseDhcp; }
    const struct in_addr &getIp() const { return mIp; }
    const struct in_addr &getNetmask() const { return mNetmask; }
    const struct in_addr &getGateway() const { return mGateway; }
    const struct in_addr &getDns1() const { return mDns1; }
    const struct in_addr &getDns2() const { return mDns2; }
    const struct in_addr &getDns3() const { return mDns3; }
};


#endif
