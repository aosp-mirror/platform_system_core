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

    class WifiScanCmd : public NexusCommand {
    public:
        WifiScanCmd();
        virtual ~WifiScanCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class WifiScanResultsCmd : public NexusCommand {
    public:
        WifiScanResultsCmd();
        virtual ~WifiScanResultsCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class WifiCreateNetworkCmd : public NexusCommand {
    public:
        WifiCreateNetworkCmd();
        virtual ~WifiCreateNetworkCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class WifiRemoveNetworkCmd : public NexusCommand {
    public:
        WifiRemoveNetworkCmd();
        virtual ~WifiRemoveNetworkCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class WifiListNetworksCmd : public NexusCommand {
    public:
        WifiListNetworksCmd();
        virtual ~WifiListNetworksCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class SetCmd : public NexusCommand {
    public:
        SetCmd();
        virtual ~SetCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class GetCmd : public NexusCommand {
    public:
        GetCmd();
        virtual ~GetCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };

    class ListCmd : public NexusCommand {
    public:
        ListCmd();
        virtual ~ListCmd() {}
        int runCommand(SocketClient *c, int argc, char ** argv);
    };
};

#endif
