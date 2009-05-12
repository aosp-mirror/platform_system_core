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

#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "Controller.h"
#include "NetworkManager.h"
#include "WifiController.h"

CommandListener::CommandListener() :
                 FrameworkListener("nexus") {
    registerCmd(new WifiEnableCmd());
    registerCmd(new WifiDisableCmd());
    registerCmd(new WifiScanCmd());
    registerCmd(new WifiScanResultsCmd());

    registerCmd(new VpnEnableCmd());
    registerCmd(new VpnDisableCmd());
}
 
/* -------------
 * Wifi Commands
 * ------------ */

CommandListener::WifiEnableCmd::WifiEnableCmd() :
                 NexusCommand("wifi_enable") {
} 
               
int CommandListener::WifiEnableCmd::runCommand(SocketClient *cli, char *data) {
    Controller *c = NetworkManager::Instance()->findController("WIFI");

    if (c->enable())
        cli->sendMsg(400, "Failed to enable wifi", true);
    else
        cli->sendMsg(200, "Wifi Enabled", false);
    return 0;
}

CommandListener::WifiDisableCmd::WifiDisableCmd() :
                 NexusCommand("wifi_disable") {
} 
               
int CommandListener::WifiDisableCmd::runCommand(SocketClient *cli, char *data) {
    Controller *c = NetworkManager::Instance()->findController("WIFI");

    if (c->disable())
        cli->sendMsg(400, "Failed to disable wifi", true);
    else
        cli->sendMsg(200, "Wifi Disabled", false);
    return 0;
}

CommandListener::WifiScanCmd::WifiScanCmd() :
                 NexusCommand("wifi_scan") {
} 

int CommandListener::WifiScanCmd::runCommand(SocketClient *cli, char *data) {
    LOGD("WifiScanCmd(%s)", data);

    WifiController *wc = (WifiController *) NetworkManager::Instance()->findController("WIFI");

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

    if (wc->setScanMode(mode))
        cli->sendMsg(400, "Failed to set scan mode", true);
    else
        cli->sendMsg(200, "Scan mode set", false);

    return 0;
}

CommandListener::WifiScanResultsCmd::WifiScanResultsCmd() :
                 NexusCommand("wifi_scan_results") {
} 

int CommandListener::WifiScanResultsCmd::runCommand(SocketClient *cli, char *data) {
    NetworkManager *nm = NetworkManager::Instance();

    WifiController *wc = (WifiController *) nm->findController("WIFI");

    ScanResultCollection *src = wc->createScanResults();
    ScanResultCollection::iterator it;
    char buffer[256];
    
    for(it = src->begin(); it != src->end(); ++it) {
        sprintf(buffer, "%s:%u:%d:%s:%s",
                (*it)->getBssid(), (*it)->getFreq(), (*it)->getLevel(),
                (*it)->getFlags(), (*it)->getSsid());
        cli->sendMsg(125, buffer, false);
        delete (*it);
        it = src->erase(it);
    }

    delete src;
    cli->sendMsg(200, "Scan results complete", false);
    return 0;
}

/* ------------
 * Vpn Commands
 * ------------ */
CommandListener::VpnEnableCmd::VpnEnableCmd() :
                 NexusCommand("vpn_enable") {
} 
               
int CommandListener::VpnEnableCmd::runCommand(SocketClient *cli, char *data) {
    Controller *c = NetworkManager::Instance()->findController("VPN");

    if (c->enable())
        cli->sendMsg(400, "Failed to enable VPN", true);
    else
        cli->sendMsg(200, "VPN enabled", false);
    return 0;
}

CommandListener::VpnDisableCmd::VpnDisableCmd() :
                 NexusCommand("vpn_disable") {
} 
               
int CommandListener::VpnDisableCmd::runCommand(SocketClient *cli, char *data) {
    Controller *c = NetworkManager::Instance()->findController("VPN");

    if (c->disable())
        cli->sendMsg(400, "Failed to disable VPN", true);
    else
        cli->sendMsg(200, "VPN disabled", false);
    return 0;
}
