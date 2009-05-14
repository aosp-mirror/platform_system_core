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
#ifndef _COMMANDLISTENER_H__
#define _COMMANDLISTENER_H__

#include <sysutils/FrameworkListener.h>
#include "NexusCommand.h"

class CommandListener : public FrameworkListener {
public:
    CommandListener();
    virtual ~CommandListener() {}

private:
    class WifiEnableCmd : public NexusCommand {
    public:
        WifiEnableCmd();
        virtual ~WifiEnableCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiDisableCmd : public NexusCommand {
    public:
        WifiDisableCmd();
        virtual ~WifiDisableCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiScanCmd : public NexusCommand {
    public:
        WifiScanCmd();
        virtual ~WifiScanCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiScanResultsCmd : public NexusCommand {
    public:
        WifiScanResultsCmd();
        virtual ~WifiScanResultsCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiAddNetworkCmd : public NexusCommand {
    public:
        WifiAddNetworkCmd();
        virtual ~WifiAddNetworkCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiRemoveNetworkCmd : public NexusCommand {
    public:
        WifiRemoveNetworkCmd();
        virtual ~WifiRemoveNetworkCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiListNetworksCmd : public NexusCommand {
    public:
        WifiListNetworksCmd();
        virtual ~WifiListNetworksCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiSetVarCmd : public NexusCommand {
    public:
        WifiSetVarCmd();
        virtual ~WifiSetVarCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class WifiGetVarCmd : public NexusCommand {
    public:
        WifiGetVarCmd();
        virtual ~WifiGetVarCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class VpnEnableCmd : public NexusCommand {
    public:
        VpnEnableCmd();
        virtual ~VpnEnableCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class VpnSetVarCmd : public NexusCommand {
    public:
        VpnSetVarCmd();
        virtual ~VpnSetVarCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class VpnGetVarCmd : public NexusCommand {
    public:
        VpnGetVarCmd();
        virtual ~VpnGetVarCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

    class VpnDisableCmd : public NexusCommand {
    public:
        VpnDisableCmd();
        virtual ~VpnDisableCmd() {}
        int runCommand(SocketClient *c, char *data);
    };

};

#endif
