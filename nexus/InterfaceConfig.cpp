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

#include <string.h>

#define LOG_TAG "InterfaceConfig"
#include <cutils/log.h>

#include "InterfaceConfig.h"

InterfaceConfig::InterfaceConfig(const char *name) {
    mName = strdup(name);
    mUseDhcp = true;
}

InterfaceConfig::~InterfaceConfig() {
    free(mName);
}

InterfaceConfig::InterfaceConfig(const char *name, const char *ip, const char *nm,
                    const char *gw, const char *dns1, const char *dns2,
                    const char *dns3) {
    mName = strdup(name);
    mUseDhcp = false;

    if (!inet_aton(ip, &mIp))
        LOGW("Unable to parse ip (%s)", ip);
    if (!inet_aton(nm, &mIp))
        LOGW("Unable to parse netmask (%s)", nm);
    if (!inet_aton(gw, &mIp))
        LOGW("Unable to parse gateway (%s)", gw);
    if (!inet_aton(dns1, &mIp))
        LOGW("Unable to parse dns1 (%s)", dns1);
    if (!inet_aton(dns2, &mIp))
        LOGW("Unable to parse dns2 (%s)", dns2);
    if (!inet_aton(dns3, &mIp))
        LOGW("Unable to parse dns3 (%s)", dns3);
}

InterfaceConfig::InterfaceConfig(const char *name, const struct in_addr *ip,
                    const struct in_addr *nm, const struct in_addr *gw,
                    const struct in_addr *dns1, const struct in_addr *dns2,
                    const struct in_addr *dns3) {
    mName = strdup(name);
    mUseDhcp = false;

    memcpy(&mIp, ip, sizeof(struct in_addr));
    memcpy(&mNetmask, nm, sizeof(struct in_addr));
    memcpy(&mGateway, gw, sizeof(struct in_addr));
    memcpy(&mDns1, dns1, sizeof(struct in_addr));
    memcpy(&mDns2, dns2, sizeof(struct in_addr));
    memcpy(&mDns3, dns3, sizeof(struct in_addr));
}

