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
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "VpnController.h"

VpnController::VpnController() :
               Controller("VPN") {
}

int VpnController::start() {
    errno = ENOSYS;
    return -1;
}

int VpnController::stop() {
    errno = ENOSYS;
    return -1;
}

int VpnController::enable() {
    errno = ENOSYS;
    return -1;
}

int VpnController::disable() {
    errno = ENOSYS;
    return -1;
}

int VpnController::setVpnGateway(const char *vpnGw) {
    if (!inet_aton(vpnGw, &mVpnGateway)) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

int VpnController::setVpnGateway(struct in_addr *vpnGw) {
    memcpy(&mVpnGateway, vpnGw, sizeof(struct in_addr));
    return 0;
}
