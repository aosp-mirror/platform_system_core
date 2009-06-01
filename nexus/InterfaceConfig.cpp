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

const char *InterfaceConfig::PropertyNames[] = { "dhcp", "ip",
                                                 "netmask",
                                                 "gateway", "dns1", "dns2",
                                                 "dns3", '\0' };

InterfaceConfig::InterfaceConfig(const char *prop_prefix) {
    mPropPrefix = strdup(prop_prefix);
    mUseDhcp = true;
    registerProperties();
}

InterfaceConfig::~InterfaceConfig() {
    unregisterProperties();
    free(mPropPrefix);
}

InterfaceConfig::InterfaceConfig(const char *prop_prefix,
                    const char *ip, const char *nm,
                    const char *gw, const char *dns1, const char *dns2,
                    const char *dns3) {
    mPropPrefix = strdup(prop_prefix);
    mUseDhcp = false;

    if (!inet_aton(ip, &mIp))
        LOGW("Unable to parse ip (%s)", ip);
    if (!inet_aton(nm, &mNetmask))
        LOGW("Unable to parse netmask (%s)", nm);
    if (!inet_aton(gw, &mGateway))
        LOGW("Unable to parse gateway (%s)", gw);
    if (!inet_aton(dns1, &mDns1))
        LOGW("Unable to parse dns1 (%s)", dns1);
    if (!inet_aton(dns2, &mDns2))
        LOGW("Unable to parse dns2 (%s)", dns2);
    if (!inet_aton(dns3, &mDns3))
        LOGW("Unable to parse dns3 (%s)", dns3);
    registerProperties();
}

InterfaceConfig::InterfaceConfig(const char *prop_prefix,
                    const struct in_addr *ip,
                    const struct in_addr *nm, const struct in_addr *gw,
                    const struct in_addr *dns1, const struct in_addr *dns2,
                    const struct in_addr *dns3) {
    mPropPrefix = strdup(prop_prefix);
    mUseDhcp = false;

    memcpy(&mIp, ip, sizeof(struct in_addr));
    memcpy(&mNetmask, nm, sizeof(struct in_addr));
    memcpy(&mGateway, gw, sizeof(struct in_addr));
    memcpy(&mDns1, dns1, sizeof(struct in_addr));
    memcpy(&mDns2, dns2, sizeof(struct in_addr));
    memcpy(&mDns3, dns3, sizeof(struct in_addr));
    registerProperties();
}

int InterfaceConfig::registerProperties() {
    for (const char **p = InterfaceConfig::PropertyNames; *p != '\0'; p++) {
        char *tmp;
        asprintf(&tmp, "%s.if.%s", mPropPrefix, *p);

        if (NetworkManager::Instance()->getPropMngr()->registerProperty(tmp,
                                                                        this)) {
            free(tmp);
            return -1;
        }
        free(tmp);
    }
    return 0;
}

int InterfaceConfig::unregisterProperties() {
    for (const char **p = InterfaceConfig::PropertyNames; *p != '\0'; p++) {
        char *tmp;
        asprintf(&tmp, "%s.if.%s", mPropPrefix, *p);

        if (NetworkManager::Instance()->getPropMngr()->unregisterProperty(tmp))
            LOGW("Unable to remove property '%s' (%s)", tmp, strerror(errno));
        free(tmp);
    }
    return 0;
}

int InterfaceConfig::set(const char *name, const char *value) {
    const char *n;

    for (n = &name[strlen(name)]; *n != '.'; n--);
    n++;

    if (!strcasecmp(n, "name")) {
        errno = EROFS;
        return -1;
    } else if (!strcasecmp(n, "ip") && !inet_aton(value, &mIp))
        goto out_inval;
    else if (!strcasecmp(n, "dhcp"))
        mUseDhcp = (atoi(value) == 0 ? false : true);
    else if (!strcasecmp(n, "netmask") && !inet_aton(value, &mNetmask))
        goto out_inval;
    else if (!strcasecmp(n, "gateway") && !inet_aton(value, &mGateway))
        goto out_inval;
    else if (!strcasecmp(n, "dns1") && !inet_aton(value, &mDns1))
        goto out_inval;
    else if (!strcasecmp(n, "dns2") && !inet_aton(value, &mDns2))
        goto out_inval;
    else if (!strcasecmp(n, "dns3") && !inet_aton(value, &mDns3))
        goto out_inval;
    else {
        errno = ENOENT;
        return -1;
    }

    return 0;

out_inval:
    errno = EINVAL;
    return -1;
}

const char *InterfaceConfig::get(const char *name, char *buffer, size_t max) {
    const char *n;

    for (n = &name[strlen(name)]; *n != '.'; n--);
    n++;

    if (!strcasecmp(n, "ip"))
        strncpy(buffer, inet_ntoa(mIp), max);
    else if (!strcasecmp(n, "dhcp"))
        snprintf(buffer, max, "%d", mUseDhcp);
    else if (!strcasecmp(n, "netmask"))
        strncpy(buffer, inet_ntoa(mNetmask), max);
    else if (!strcasecmp(n, "gateway"))
        strncpy(buffer, inet_ntoa(mGateway), max);
    else if (!strcasecmp(n, "dns1"))
        strncpy(buffer, inet_ntoa(mDns1), max);
    else if (!strcasecmp(n, "dns2"))
        strncpy(buffer, inet_ntoa(mDns2), max);
    else if (!strcasecmp(n, "dns3"))
        strncpy(buffer, inet_ntoa(mDns3), max);
    else {
        strncpy(buffer, "(internal error)", max);
        errno = ENOENT;
        return NULL;
    }
    return buffer;
}
