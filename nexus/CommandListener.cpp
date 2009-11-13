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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#define LOG_TAG "CommandListener"
#include <cutils/log.h>

#include <sysutils/SocketClient.h>

#include "CommandListener.h"
#include "Controller.h"
#include "Property.h"
#include "NetworkManager.h"
#include "WifiController.h"
#include "VpnController.h"
#include "ResponseCode.h"

CommandListener::CommandListener() :
                 FrameworkListener("nexus") {
    registerCmd(new WifiScanResultsCmd());
    registerCmd(new WifiListNetworksCmd());
    registerCmd(new WifiCreateNetworkCmd());
    registerCmd(new WifiRemoveNetworkCmd());

    registerCmd(new GetCmd());
    registerCmd(new SetCmd());
    registerCmd(new ListCmd());
}

/* -------------
 * Wifi Commands
 * ------------ */

CommandListener::WifiCreateNetworkCmd::WifiCreateNetworkCmd() :
                 NexusCommand("wifi_create_network") {
}

int CommandListener::WifiCreateNetworkCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");
    WifiNetwork *wn;

    if (!(wn = wc->createNetwork()))
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to create network", true);
    else {
        char tmp[128];
        sprintf(tmp, "Created network id %d.", wn->getNetworkId());
        cli->sendMsg(ResponseCode::CommandOkay, tmp, false);
    }
    return 0;
}

CommandListener::WifiRemoveNetworkCmd::WifiRemoveNetworkCmd() :
                 NexusCommand("wifi_remove_network") {
}

int CommandListener::WifiRemoveNetworkCmd::runCommand(SocketClient *cli,
                                                      int argc, char **argv) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");

    if (wc->removeNetwork(atoi(argv[1])))
        cli->sendMsg(ResponseCode::OperationFailed, "Failed to remove network", true);
    else {
        cli->sendMsg(ResponseCode::CommandOkay, "Network removed.", false);
    }
    return 0;
}

CommandListener::WifiScanResultsCmd::WifiScanResultsCmd() :
                 NexusCommand("wifi_scan_results") {
}

int CommandListener::WifiScanResultsCmd::runCommand(SocketClient *cli,
                                                    int argc, char **argv) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");

    ScanResultCollection *src = wc->createScanResults();
    ScanResultCollection::iterator it;
    char buffer[256];

    for(it = src->begin(); it != src->end(); ++it) {
        sprintf(buffer, "%s %u %d %s %s",
                (*it)->getBssid(), (*it)->getFreq(), (*it)->getLevel(),
                (*it)->getFlags(), (*it)->getSsid());
        cli->sendMsg(ResponseCode::WifiScanResult, buffer, false);
        delete (*it);
        it = src->erase(it);
    }

    delete src;
    cli->sendMsg(ResponseCode::CommandOkay, "Scan results complete.", false);
    return 0;
}

CommandListener::WifiListNetworksCmd::WifiListNetworksCmd() :
                 NexusCommand("wifi_list_networks") {
}

int CommandListener::WifiListNetworksCmd::runCommand(SocketClient *cli,
                                                     int argc, char **argv) {
    NetworkManager *nm = NetworkManager::Instance();
    WifiController *wc = (WifiController *) nm->findController("WIFI");

    WifiNetworkCollection *src = wc->createNetworkList();
    WifiNetworkCollection::iterator it;
    char buffer[256];

    for(it = src->begin(); it != src->end(); ++it) {
        sprintf(buffer, "%d:%s", (*it)->getNetworkId(), (*it)->getSsid());
        cli->sendMsg(ResponseCode::WifiNetworkList, buffer, false);
        delete (*it);
    }

    delete src;
    cli->sendMsg(ResponseCode::CommandOkay, "Network listing complete.", false);
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

int CommandListener::GetCmd::runCommand(SocketClient *cli, int argc, char **argv) {
    char val[Property::ValueMaxSize];

    if (!NetworkManager::Instance()->getPropMngr()->get(argv[1],
                                                        val,
                                                        sizeof(val))) {
        goto out_inval;
    }

    char *tmp;
    asprintf(&tmp, "%s %s", argv[1], val);
    cli->sendMsg(ResponseCode::PropertyRead, tmp, false);
    free(tmp);

    cli->sendMsg(ResponseCode::CommandOkay, "Property read.", false);
    return 0;
out_inval:
    errno = EINVAL;
    cli->sendMsg(ResponseCode::CommandParameterError, "Failed to read property.", true);
    return 0;
}

CommandListener::SetCmd::SetCmd() :
                 NexusCommand("set") {
}

int CommandListener::SetCmd::runCommand(SocketClient *cli, int argc,
                                        char **argv) {
    if (NetworkManager::Instance()->getPropMngr()->set(argv[1], argv[2]))
        goto out_inval;

    cli->sendMsg(ResponseCode::CommandOkay, "Property set.", false);
    return 0;

out_inval:
    errno = EINVAL;
    cli->sendMsg(ResponseCode::CommandParameterError, "Failed to set property.", true);
    return 0;
}

CommandListener::ListCmd::ListCmd() :
                 NexusCommand("list") {
}

int CommandListener::ListCmd::runCommand(SocketClient *cli, int argc, char **argv) {
    android::List<char *> *pc;
    char *prefix = NULL;

    if (argc > 1)
        prefix = argv[1];

    if (!(pc = NetworkManager::Instance()->getPropMngr()->createPropertyList(prefix))) {
        errno = ENODATA;
        cli->sendMsg(ResponseCode::CommandParameterError, "Failed to list properties.", true);
        return 0;
    }

    android::List<char *>::iterator it;

    for (it = pc->begin(); it != pc->end(); ++it) {
        char p_v[Property::ValueMaxSize];

        if (!NetworkManager::Instance()->getPropMngr()->get((*it),
                                                            p_v,
                                                            sizeof(p_v))) {
            LOGW("Failed to get %s (%s)", (*it), strerror(errno));
        }

        char *buf;
        if (asprintf(&buf, "%s %s", (*it), p_v) < 0) {
            LOGE("Failed to allocate memory");
            free((*it));
            continue;
        }
        cli->sendMsg(ResponseCode::PropertyList, buf, false);
        free(buf);

        free((*it));
    }

    delete pc;

    cli->sendMsg(ResponseCode::CommandOkay, "Properties list complete.", false);
    return 0;
}
