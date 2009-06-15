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
#include <netinet/in.h>
#include <arpa/inet.h>

#define LOG_TAG "OpenVpnController"
#include <cutils/log.h>
#include <cutils/properties.h>

#include <sysutils/ServiceManager.h>

#include "OpenVpnController.h"
#include "PropertyManager.h"

#define DAEMON_PROP_NAME "vpn.openvpn.status"
#define DAEMON_CONFIG_FILE "/data/misc/openvpn/openvpn.conf"

OpenVpnController::OpenVpnController(PropertyManager *propmngr,
                                     IControllerHandler *handlers) :
                   VpnController(propmngr, handlers) {
    mServiceManager = new ServiceManager();
}

OpenVpnController::~OpenVpnController() {
    delete mServiceManager;
}

int OpenVpnController::start() {
    return VpnController::start();
}

int OpenVpnController::stop() {
    return VpnController::stop();
}

int OpenVpnController::enable() {
    char svc[PROPERTY_VALUE_MAX];
    char tmp[64];

    if (!mPropMngr->get("vpn.gateway", tmp, sizeof(tmp))) {
        LOGE("Error reading property 'vpn.gateway' (%s)", strerror(errno));
        return -1;
    }
    snprintf(svc, sizeof(svc), "openvpn:--remote %s 1194", tmp);

    if (mServiceManager->start(svc))
        return -1;

    return 0;
}

int OpenVpnController::disable() {
    if (mServiceManager->stop("openvpn"))
        return -1;
    return 0;
}
