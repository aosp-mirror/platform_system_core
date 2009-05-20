/*
 * Copyright (C) ErrorCode::CommandOkay8 The Android Open Source Project
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define LOG_TAG "CommandListener"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "Controller.h"
#include "NetworkManager.h"
#include "WifiController.h"
#include "VpnController.h"
#include "ErrorCode.h"

CommandListener::CommandListener() :
                 FrameworkListener("nexus") {
    registerCmd(new WifiScanResultsCmd());
    registerCmd(new WifiListNetworksCmd());
    registerCmd(new WifiAddNetworkCmd());
    registerCmd(new WifiRemoveNetworkCmd());

    registerCmd(new GetCmd());
    registerCmd(new SetCmd());
}
 
/* -------------
 * Wifi Commands
 * ------------ */

CommandListener::WifiAddNetworkCmd::WifiAddNetworkCmd() :
                 NexusCommand("wifi_add_network") {
} 
               
int CommandListener::WifiAddNetworkCmd::runCommand(SocketClient *cli, char *data) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");
    int networkId;

    if ((networkId = wc->addNetwork()) < 0)
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to add network", true);
    else {
        char tmp[128];
        sprintf(tmp, "Added network id %d.", networkId);
        cli->sendMsg(ErrorCode::CommandOkay, tmp, false);
    }
    return 0;
}

CommandListener::WifiRemoveNetworkCmd::WifiRemoveNetworkCmd() :
                 NexusCommand("wifi_remove_network") {
} 
               
int CommandListener::WifiRemoveNetworkCmd::runCommand(SocketClient *cli, char *data) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");

    if (wc->removeNetwork(atoi(data)))
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to remove network", true);
    else {
        cli->sendMsg(ErrorCode::CommandOkay, "Network removed.", false);
    }
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
        cli->sendMsg(ErrorCode::WifiScanResult, buffer, false);
        delete (*it);
        it = src->erase(it);
    }

    delete src;
    cli->sendMsg(ErrorCode::CommandOkay, "Scan results complete", false);
    return 0;
}

CommandListener::WifiListNetworksCmd::WifiListNetworksCmd() :
                 NexusCommand("wifi_list_networks") {
} 

int CommandListener::WifiListNetworksCmd::runCommand(SocketClient *cli, char *data) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");

    WifiNetworkCollection *src = wc->createNetworkList();
    WifiNetworkCollection::iterator it;
    char buffer[256];
    
    for(it = src->begin(); it != src->end(); ++it) {
        sprintf(buffer, "%d:%s", (*it)->getNetworkId(), (*it)->getSsid());
        cli->sendMsg(ErrorCode::WifiNetworkList, buffer, false);
        delete (*it);
        it = src->erase(it);
    }

    delete src;
    cli->sendMsg(ErrorCode::CommandOkay, "Network listing complete.", false);
    return 0;
}

/* ------------
 * Vpn Commands
 * ------------ */

/* ----------------
 * Generic Commands
 * ---------------- */
CommandListener::GetCmd::GetCmd() :
                 NexusCommand("get") {
} 

int CommandListener::GetCmd::runCommand(SocketClient *cli, char *data) {
    char *bword;
    char *last;
    char propname[32];

    if (!(bword = strtok_r(data, ":", &last)))
        goto out_inval;
   
    strncpy(propname, bword, sizeof(propname));

    char pb[255];
    snprintf(pb, sizeof(pb), "%s:", propname);

    if (!NetworkManager::Instance()->getProperty(propname,
                                                 &pb[strlen(pb)],
                                                 sizeof(pb) - strlen(pb))) {
        goto out_inval;
    }

    cli->sendMsg(ErrorCode::VariableRead, pb, false);

    cli->sendMsg(ErrorCode::CommandOkay, "Property read.", false);
    return 0;
out_inval:
    errno = EINVAL;
    cli->sendMsg(ErrorCode::CommandParameterError, "Failed to get variable.", true);
    return 0;
}

CommandListener::SetCmd::SetCmd() :
                 NexusCommand("set") {
}

int CommandListener::SetCmd::runCommand(SocketClient *cli, char *data) {
    char *bword;
    char *last;
    char propname[32];
    char propval[250];

    if (!(bword = strtok_r(data, ":", &last)))
        goto out_inval;

    strncpy(propname, bword, sizeof(propname));

    if (!(bword = strtok_r(NULL, ":", &last)))
        goto out_inval;

    strncpy(propval, bword, sizeof(propval));

    if (NetworkManager::Instance()->setProperty(propname, propval))
        goto out_inval;

    cli->sendMsg(ErrorCode::CommandOkay, "Property set.", false);
    return 0;

out_inval:
    errno = EINVAL;
    cli->sendMsg(ErrorCode::CommandParameterError, "Failed to set property.", true);
    return 0;
}
