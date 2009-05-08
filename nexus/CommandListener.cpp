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

#define LOG_TAG "CommandListener"
#include <cutils/log.h>

#include "CommandListener.h"
#include "Controller.h"
#include "NetworkManager.h"
#include "WifiController.h"

CommandListener::CommandListener(NetworkManager *netman) :
                 FrameworkListener("nexus") {
    mNetman = netman;

    registerCmd(new WifiEnableCmd(netman));
    registerCmd(new WifiDisableCmd(netman));
    registerCmd(new WifiScanCmd(netman));

    registerCmd(new VpnEnableCmd(netman));
    registerCmd(new VpnDisableCmd(netman));
}
 
/* -------------
 * Wifi Commands
 * ------------ */

CommandListener::WifiEnableCmd::WifiEnableCmd(NetworkManager *netman) :
                 NexusCommand("wifi_enable", netman) {
} 
               
int CommandListener::WifiEnableCmd::runCommand(char *data) {
    Controller *c = mNetman->findController("WIFI");
    char buffer[32];

    sprintf(buffer, "WIFI_ENABLE:%d", (c->enable() ? errno : 0));
    mNetman->getFrameworkManager()->sendMsg(buffer);
    return 0;
}

CommandListener::WifiDisableCmd::WifiDisableCmd(NetworkManager *netman) :
                 NexusCommand("wifi_disable", netman) {
} 
               
int CommandListener::WifiDisableCmd::runCommand(char *data) {
    Controller *c = mNetman->findController("WIFI");
    char buffer[32];

    sprintf(buffer, "WIFI_DISABLE:%d", (c->disable() ? errno : 0));
    mNetman->getFrameworkManager()->sendMsg(buffer);
    return 0;
}

CommandListener::WifiScanCmd::WifiScanCmd(NetworkManager *netman) :
                 NexusCommand("wifi_scan", netman) {
} 

int CommandListener::WifiScanCmd::runCommand(char *data) {
    LOGD("WifiScanCmd(%s)", data);
    WifiController *wc = (WifiController *) mNetman->findController("WIFI");
    char buffer[32];
    int mode = 0;
    char *bword, *last;

    if (!(bword = strtok_r(data, ":", &last))) {
        errno = EINVAL;
        return -1;
    }

    if (!(bword = strtok_r(NULL, ":", &last))) {
        errno = EINVAL;
        return -1;
    }

    mode = atoi(bword);

    sprintf(buffer, "WIFI_SCAN:%d", (wc->setScanMode(mode) ? errno : 0));
    mNetman->getFrameworkManager()->sendMsg(buffer);
    return 0;
}

/* ------------
 * Vpn Commands
 * ------------ */
CommandListener::VpnEnableCmd::VpnEnableCmd(NetworkManager *netman) :
                 NexusCommand("vpn_enable", netman) {
} 
               
int CommandListener::VpnEnableCmd::runCommand(char *data) {
    Controller *c = mNetman->findController("VPN");
    char buffer[32];

    sprintf(buffer, "VPN_ENABLE:%d", (c->enable() ? errno : 0));
    mNetman->getFrameworkManager()->sendMsg(buffer);
    return 0;
}

CommandListener::VpnDisableCmd::VpnDisableCmd(NetworkManager *netman) :
                 NexusCommand("vpn_disable", netman) {
} 
               
int CommandListener::VpnDisableCmd::runCommand(char *data) {
    Controller *c = mNetman->findController("VPN");
    char buffer[32];

    sprintf(buffer, "VPN_DISABLE:%d", (c->disable() ? errno : 0));
    mNetman->getFrameworkManager()->sendMsg(buffer);
    return 0;
}
