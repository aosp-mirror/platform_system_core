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

class NetworkManager;

class CommandListener : public FrameworkListener {
protected:
    NetworkManager *mNetman;

public:
    CommandListener(NetworkManager *netman);
    virtual ~CommandListener() {}

private:
    class WifiEnableCmd : public NexusCommand {
    public:
        WifiEnableCmd(NetworkManager *);
        virtual ~WifiEnableCmd() {}
        int runCommand(char *data);
    };

    class WifiDisableCmd : public NexusCommand {
    public:
        WifiDisableCmd(NetworkManager *);
        virtual ~WifiDisableCmd() {}
        int runCommand(char *data);
    };

    class WifiScanCmd : public NexusCommand {
    public:
        WifiScanCmd(NetworkManager *);
        virtual ~WifiScanCmd() {}
        int runCommand(char *data);
    };

    class VpnEnableCmd : public NexusCommand {
    public:
        VpnEnableCmd(NetworkManager *);
        virtual ~VpnEnableCmd() {}
        int runCommand(char *data);
    };

    class VpnDisableCmd : public NexusCommand {
    public:
        VpnDisableCmd(NetworkManager *);
        virtual ~VpnDisableCmd() {}
        int runCommand(char *data);
    };

};

#endif
