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

#ifndef _NETWORKMANAGER_H
#define _NETWORKMANAGER_H

#include <sysutils/SocketListener.h>

#include "Controller.h"
#include "PropertyManager.h"
#include "IControllerHandler.h"
#include "IDhcpEventHandlers.h"

class InterfaceConfig;
class DhcpClient;

class NetworkManager : public IControllerHandler, public IDhcpEventHandlers {
private:
    static NetworkManager *sInstance;

private:
    ControllerCollection *mControllers;
    SocketListener       *mBroadcaster;
    PropertyManager      *mPropMngr;
    DhcpClient           *mDhcp;

public:
    virtual ~NetworkManager();

    int run();

    int attachController(Controller *controller);

    Controller *findController(const char *name);

    void setBroadcaster(SocketListener *sl) { mBroadcaster = sl; }
    SocketListener *getBroadcaster() { return mBroadcaster; }
    PropertyManager *getPropMngr() { return mPropMngr; }

    static NetworkManager *Instance();

private:
    int startControllers();
    int stopControllers();

    NetworkManager(PropertyManager *propMngr);

    void onInterfaceConnected(Controller *c, const InterfaceConfig *cfg);
    void onInterfaceDisconnected(Controller *c, const char *name);
};
#endif
