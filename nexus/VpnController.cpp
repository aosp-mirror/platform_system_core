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
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "PropertyManager.h"
#include "VpnController.h"

VpnController::VpnController(PropertyManager *propmngr,
                             IControllerHandler *handlers) :
               Controller("VPN", propmngr, handlers) {
    mEnabled = false;
}

int VpnController::start() {
    mPropMngr->registerProperty("vpn.enabled", this);
    return 0;
}

int VpnController::stop() {
    mPropMngr->unregisterProperty("vpn.enabled");
    return 0;
}

int VpnController::set(const char *name, const char *value) {
    if (!strcmp(name, "vpn.enabled")) {
        int en = atoi(value);
        int rc;

        if (en == mEnabled)
            return 0;
        rc = (en ? enable() : disable());

        if (!rc) {
            mEnabled = en;
            if (en) 
                mPropMngr->unregisterProperty("vpn.gateway");
            else
                mPropMngr->unregisterProperty("vpn.gateway");
        }
        return rc;
    } if (!strcmp(name, "vpn.gateway")) {
        if (!inet_aton(value, &mVpnGateway)) {
            errno = EINVAL;
            return -1;
        }
        return 0;
    }

    return Controller::set(name, value);
}

const char *VpnController::get(const char *name, char *buffer, size_t maxsize) {
    if (!strcmp(name, "vpn.enabled")) {
        snprintf(buffer, maxsize, "%d", mEnabled);
        return buffer;
    } if (!strcmp(name, "vpn.gateway")) {
        snprintf(buffer, maxsize, "%s", inet_ntoa(mVpnGateway));
        return buffer;
    }

    return Controller::get(name, buffer, maxsize);
}
