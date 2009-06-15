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
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include <cutils/properties.h>
#define LOG_TAG "TiwlanWifiController"
#include <cutils/log.h>

#include "PropertyManager.h"
#include "TiwlanWifiController.h"

#define DRIVER_PROP_NAME "wlan.driver.status"

extern "C" int sched_yield(void);

TiwlanWifiController::TiwlanWifiController(PropertyManager *propmngr,
                                           IControllerHandler *handlers,
                                           char *modpath, char *modname,
                                           char *modargs) :
                      WifiController(propmngr, handlers, modpath, modname,
                                     modargs) {
}

int TiwlanWifiController::powerUp() {
    return 0; // Powerup is currently done when the driver is loaded
}

int TiwlanWifiController::powerDown() {
    return 0; // Powerdown is currently done when the driver is unloaded
}

bool TiwlanWifiController::isPoweredUp() {
    return isKernelModuleLoaded(getModuleName());
}

int TiwlanWifiController::loadFirmware() {
    char driver_status[PROPERTY_VALUE_MAX];
    int count = 100;

    property_set("ctl.start", "wlan_loader");
    sched_yield();

    // Wait for driver to be ready
    while (count-- > 0) {
        if (property_get(DRIVER_PROP_NAME, driver_status, NULL)) {
            if (strcmp(driver_status, "ok") == 0)
                return 0;
            else if (strcmp(DRIVER_PROP_NAME, "failed") == 0)
                return -1;
        }
        usleep(200000);
    }
    property_set(DRIVER_PROP_NAME, "timeout");
    return -1;
}

bool TiwlanWifiController::isFirmwareLoaded() {
    // Always load the firmware
    return false;
}
