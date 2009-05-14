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

#define DAEMON_PROP_NAME "vpn.openvpn.status"
#define DAEMON_CONFIG_FILE "/data/misc/openvpn/openvpn.conf"

OpenVpnController::OpenVpnController() :
                   VpnController() {
    mServiceManager = new ServiceManager();
}

OpenVpnController::~OpenVpnController() {
    delete mServiceManager;
}

int OpenVpnController::start() {
    return 0;
}

int OpenVpnController::stop() {
    return 0;
}

int OpenVpnController::enable() {

    if (validateConfig()) {
        LOGE("Error validating configuration file");
        return -1;
    }

    if (mServiceManager->start("openvpn"))
        return -1;

    return 0;
}

int OpenVpnController::disable() {

    if (mServiceManager->stop("openvpn"))
        return -1;
    return 0;
}

int OpenVpnController::validateConfig() {
    unlink(DAEMON_CONFIG_FILE);

    FILE *fp = fopen(DAEMON_CONFIG_FILE, "w");
    if (!fp)
        return -1;

    fprintf(fp, "remote %s 1194\n", inet_ntoa(getVpnGateway()));
    fclose(fp);
    return 0;
}
