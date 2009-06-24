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
               Controller("vpn", propmngr, handlers) {
    mEnabled = false;

    mStaticProperties.propEnabled = new VpnEnabledProperty(this);
    mDynamicProperties.propGateway = new IPV4AddressPropertyHelper("Gateway",
                                                                   false,
                                                                   &mGateway);
}

int VpnController::start() {
    mPropMngr->attachProperty("vpn", mStaticProperties.propEnabled);
    return 0;
}

int VpnController::stop() {
    mPropMngr->detachProperty("vpn", mStaticProperties.propEnabled);
    return 0;
}

VpnController::VpnIntegerProperty::VpnIntegerProperty(VpnController *c,
                                                      const char *name,
                                                      bool ro,
                                                      int elements) :
                IntegerProperty(name, ro, elements) {
    mVc = c;
}

VpnController::VpnStringProperty::VpnStringProperty(VpnController *c,
                                                    const char *name,
                                                    bool ro, int elements) :
                StringProperty(name, ro, elements) {
    mVc = c;
}

VpnController::VpnIPV4AddressProperty::VpnIPV4AddressProperty(VpnController *c,
                                                              const char *name,
                                                              bool ro, int elements) :
                IPV4AddressProperty(name, ro, elements) {
    mVc = c;
}

VpnController::VpnEnabledProperty::VpnEnabledProperty(VpnController *c) :
                VpnIntegerProperty(c, "Enabled", false, 1) {
}
int VpnController::VpnEnabledProperty::get(int idx, int *buffer) {
    *buffer = mVc->mEnabled;
    return 0;
}
int VpnController::VpnEnabledProperty::set(int idx, int value) {
    int rc;
    if (!value) {
        mVc->mPropMngr->detachProperty("vpn", mVc->mDynamicProperties.propGateway);
        rc = mVc->disable();
    } else {
        rc = mVc->enable();
        if (!rc) {
            mVc->mPropMngr->attachProperty("vpn", mVc->mDynamicProperties.propGateway);
        }
    }
    if (!rc)
        mVc->mEnabled = value;
    return rc;
}
