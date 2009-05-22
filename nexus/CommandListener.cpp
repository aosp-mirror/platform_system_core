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
    registerCmd(new WifiEnableCmd());
    registerCmd(new WifiDisableCmd());
    registerCmd(new WifiScanCmd());
    registerCmd(new WifiScanResultsCmd());
    registerCmd(new WifiListNetworksCmd());
    registerCmd(new WifiAddNetworkCmd());
    registerCmd(new WifiRemoveNetworkCmd());
    registerCmd(new WifiSetVarCmd());
    registerCmd(new WifiGetVarCmd());

    registerCmd(new VpnEnableCmd());
    registerCmd(new VpnSetVarCmd());
    registerCmd(new VpnGetVarCmd());
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
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to enable wifi", true);
    else
        cli->sendMsg(ErrorCode::CommandOkay, "Wifi Enabled", false);
    return 0;
}

CommandListener::WifiDisableCmd::WifiDisableCmd() :
                 NexusCommand("wifi_disable") {
} 
               
int CommandListener::WifiDisableCmd::runCommand(SocketClient *cli, char *data) {
    Controller *c = NetworkManager::Instance()->findController("WIFI");

    if (c->disable())
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to disable wifi", true);
    else
        cli->sendMsg(ErrorCode::CommandOkay, "Wifi Disabled", false);
    return 0;
}

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

CommandListener::WifiScanCmd::WifiScanCmd() :
                 NexusCommand("wifi_scan") {
} 

int CommandListener::WifiScanCmd::runCommand(SocketClient *cli, char *data) {
    WifiController *wc = (WifiController *) NetworkManager::Instance()->findController("WIFI");

    if (wc->setScanMode(atoi(data)))
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to set scan mode", true);
    else
        cli->sendMsg(ErrorCode::CommandOkay, "Scan mode set", false);

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

CommandListener::WifiSetVarCmd::WifiSetVarCmd() :
                 NexusCommand("wifi_setvar") {
} 

int CommandListener::WifiSetVarCmd::runCommand(SocketClient *cli, char *data) {
    WifiController *wc = (WifiController *) NetworkManager::Instance()->findController("WIFI");

    char *bword;
    char *last;
    char varname[32];
    char val[250];
    int networkId;

    if (!(bword = strtok_r(data, ":", &last)))
        goto out_inval;

    networkId = atoi(bword);
   
    if (!(bword = strtok_r(NULL, ":", &last)))
        goto out_inval;

    strncpy(varname, bword, sizeof(varname));

    if (!(bword = strtok_r(NULL, ":", &last)))
        goto out_inval;

    strncpy(val, bword, sizeof(val));

    LOGD("Network id %d, varname '%s', value '%s'", networkId, varname, val);

    return 0;

out_inval:
    errno = EINVAL;
    cli->sendMsg(ErrorCode::CommandParameterError, "Failed to set variable.", true);
    return 0;
}

CommandListener::WifiGetVarCmd::WifiGetVarCmd() :
                 NexusCommand("wifi_getvar") {
} 

int CommandListener::WifiGetVarCmd::runCommand(SocketClient *cli, char *data) {
    WifiController *wc = (WifiController *) NetworkManager::Instance()->findController("WIFI");

    char *bword;
    char *last;
    char varname[32];
    int networkId;

    if (!(bword = strtok_r(data, ":", &last)))
        goto out_inval;
   
    networkId = atoi(bword);

    if (!(bword = strtok_r(NULL, ":", &last)))
        goto out_inval;

    strncpy(varname, bword, sizeof(varname));

    LOGD("networkId = %d, varname '%s'", networkId, varname);

    return 0;
out_inval:
    errno = EINVAL;
    cli->sendMsg(ErrorCode::CommandParameterError, "Failed to get variable.", true);
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
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to enable VPN", true);
    else
        cli->sendMsg(ErrorCode::CommandOkay, "VPN enabled", false);
    return 0;
}

CommandListener::VpnSetVarCmd::VpnSetVarCmd() :
                 NexusCommand("vpn_setvar") {
} 

int CommandListener::VpnSetVarCmd::runCommand(SocketClient *cli, char *data) {
    VpnController *vc = (VpnController *) NetworkManager::Instance()->findController("VPN");

    char *bword;
    char *last;
    char varname[32];
    char val[250];

    if (!(bword = strtok_r(data, ":", &last)))
        goto out_inval;

    strncpy(varname, bword, sizeof(varname));

    if (!(bword = strtok_r(NULL, ":", &last)))
        goto out_inval;

    strncpy(val, bword, sizeof(val));

    if (!strcasecmp(varname, "vpn_gateway")) {
        if (vc->setVpnGateway(val))
            goto out_inval;
    } else {
        cli->sendMsg(ErrorCode::CommandParameterError, "Variable not found.", true);
        return 0;
    }

    cli->sendMsg(ErrorCode::CommandOkay, "Variable written.", false);
    return 0;

out_inval:
    errno = EINVAL;
    cli->sendMsg(ErrorCode::CommandParameterError, "Failed to set variable.", true);
    return 0;
}

CommandListener::VpnGetVarCmd::VpnGetVarCmd() :
                 NexusCommand("vpn_getvar") {
} 

int CommandListener::VpnGetVarCmd::runCommand(SocketClient *cli, char *data) {
    VpnController *vc = (VpnController *) NetworkManager::Instance()->findController("VPN");

    char *bword;
    char *last;
    char varname[32];

    if (!(bword = strtok_r(data, ":", &last)))
        goto out_inval;
   
    strncpy(varname, bword, sizeof(varname));

    if (!strcasecmp(varname, "vpn_gateway")) {
        char buffer[255];

        sprintf(buffer, "%s:%s", varname, inet_ntoa(vc->getVpnGateway()));
        cli->sendMsg(ErrorCode::VariableRead, buffer, false);
    } else {
        cli->sendMsg(ErrorCode::CommandParameterError, "Variable not found.", true);
        return 0;
    }

    cli->sendMsg(ErrorCode::CommandOkay, "Variable read.", false);
    return 0;
out_inval:
    errno = EINVAL;
    cli->sendMsg(ErrorCode::CommandParameterError, "Failed to get variable.", true);
    return 0;
}

CommandListener::VpnDisableCmd::VpnDisableCmd() :
                 NexusCommand("vpn_disable") {
} 
               
int CommandListener::VpnDisableCmd::runCommand(SocketClient *cli, char *data) {
    Controller *c = NetworkManager::Instance()->findController("VPN");

    if (c->disable())
        cli->sendMsg(ErrorCode::OperationFailed, "Failed to disable VPN", true);
    else
        cli->sendMsg(ErrorCode::CommandOkay, "VPN disabled", false);
    return 0;
}
