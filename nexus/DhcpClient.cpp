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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define LOG_TAG "DhcpClient"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <sysutils/ServiceManager.h>

#include "DhcpClient.h"
#include "DhcpState.h"
#include "DhcpListener.h"
#include "IDhcpEventHandlers.h"

extern "C" {
int ifc_disable(const char *ifname);
int ifc_add_host_route(const char *ifname, uint32_t addr);
int ifc_remove_host_routes(const char *ifname);
int ifc_set_default_route(const char *ifname, uint32_t gateway);
int ifc_get_default_route(const char *ifname);
int ifc_remove_default_route(const char *ifname);
int ifc_reset_connections(const char *ifname);
int ifc_configure(const char *ifname, in_addr_t ipaddr, in_addr_t netmask, in_addr_t gateway, in_addr_t dns1, in_addr_t dns2);

int dhcp_do_request(const char *ifname,
                    in_addr_t *ipaddr,
                    in_addr_t *gateway,
                    in_addr_t *mask,
                    in_addr_t *dns1,
                    in_addr_t *dns2,
                    in_addr_t *server,
                    uint32_t  *lease);
int dhcp_stop(const char *ifname);
int dhcp_release_lease(const char *ifname);
char *dhcp_get_errmsg();
}

DhcpClient::DhcpClient(IDhcpEventHandlers *handlers) :
            mState(DhcpState::STOPPED), mHandlers(handlers) {
    mServiceManager = new ServiceManager();
    mListener = NULL;
}

DhcpClient::~DhcpClient() {
    delete mServiceManager;
    if (mListener)
        delete mListener;
}

int DhcpClient::start(const char *interface) {

    char svc[PROPERTY_VALUE_MAX];
    snprintf(svc, sizeof(svc), "dhcpcd_ng:%s", interface);

    if (mServiceManager->start(svc)) {
        LOGE("Failed to start dhcp service");
        return -1;
    }

    mListener = new DhcpListener(mHandlers);
    if (mListener->startListener()) {
        LOGE("Failed to start listener");
#if 0
        mServiceManager->stop("dhcpcd_ng");
        return -1;
#endif
        delete mListener;
        mListener = NULL;
    }

    mState = DhcpState::STARTED;

    return 0;
}

int DhcpClient::stop() {
    if (mListener) {
        mListener->stopListener();
        delete mListener;
        mListener = NULL;
    }

    if (mServiceManager->stop("dhcpcd_ng")) 
        LOGW("Failed to stop DHCP service (%s)", strerror(errno));
    mState = DhcpState::STOPPED;
    return 0;
}
