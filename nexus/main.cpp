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
#include <errno.h>

#define LOG_TAG "Nexus"

#include "cutils/log.h"
#include "NetworkManager.h"
#include "CommandListener.h"

#include "LoopController.h"
#include "OpenVpnController.h"
#include "TiwlanWifiController.h"

int main() {
    LOGI("Nexus version 0.1 firing up");

    CommandListener *cl = new CommandListener();

    NetworkManager *nm;
    if (!(nm = NetworkManager::Instance())) {
        LOGE("Unable to create NetworkManager");
        exit (-1);
    };

    nm->setBroadcaster((SocketListener *) cl);

    nm->attachController(new LoopController(nm->getPropMngr(), nm));
    nm->attachController(new TiwlanWifiController(nm->getPropMngr(), nm, "/system/lib/modules/wlan.ko", "wlan", ""));
//    nm->attachController(new AndroidL2TPVpnController(nm->getPropMngr(), nm));
    nm->attachController(new OpenVpnController(nm->getPropMngr(), nm));


    if (NetworkManager::Instance()->run()) {
        LOGE("Unable to Run NetworkManager (%s)", strerror(errno));
        exit (1);
    }

    if (cl->startListener()) {
        LOGE("Unable to start CommandListener (%s)", strerror(errno));
        exit (1);
    }

    // XXX: we'll use the main thread for the NetworkManager eventually

    while(1) {
        sleep(1000);
    }

    LOGI("Nexus exiting");
    exit(0);
}
