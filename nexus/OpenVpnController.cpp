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

#define LOG_TAG "OpenVpnController"
#include <cutils/log.h>
#include <cutils/properties.h>

#include "OpenVpnController.h"

#define DAEMON_PROP_NAME "vpn.openvpn.status"

OpenVpnController::OpenVpnController() :
                   VpnController() {
}

int OpenVpnController::start() {
    return 0;
}

int OpenVpnController::stop() {
    return 0;
}

int OpenVpnController::enable() {

    // Validate configuration file
   
    // Validate key file

    if (startServiceDaemon())
        return -1;

    errno = -ENOSYS;
    return -1;
}

int OpenVpnController::startServiceDaemon() {
    char status[PROPERTY_VALUE_MAX];
    int count = 100;

    property_set("ctl.start", "openvpn");
    sched_yield();

    while (count-- > 0) {
        if (property_get(DAEMON_PROP_NAME, status, NULL)) {
            if (strcmp(status, "ok") == 0)
                return 0;
            else if (strcmp(DAEMON_PROP_NAME, "failed") == 0)
                return -1;
        }
        usleep(200000);
    }
    property_set(DAEMON_PROP_NAME, "timeout");
    return -1;
}

int OpenVpnController::stopServiceDaemon() {
    char status[PROPERTY_VALUE_MAX] = {'\0'};
    int count = 50;

    if (property_get(DAEMON_PROP_NAME, status, NULL) &&
        !strcmp(status, "stopped")) {
        LOGD("Service already stopped");
        return 0;
    }

    property_set("ctl.stop", "openvpn");
    sched_yield();

    while (count-- > 0) {
        if (property_get(DAEMON_PROP_NAME, status, NULL)) {
            if (!strcmp(status, "stopped"))
                break;
        }
        usleep(100000);
    }

    if (!count) {
        LOGD("Timed out waiting for openvpn to stop");
        errno = ETIMEDOUT;
        return -1;
    }

    return 0;
}

int OpenVpnController::disable() {
    errno = -ENOSYS;
    return -1;
}
