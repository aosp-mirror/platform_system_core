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

#include <utils/List.h>
#include <sysutils/SocketListener.h>

#include "Controller.h"
#include "PropertyManager.h"
#include "IControllerHandler.h"
#include "IDhcpEventHandlers.h"

class InterfaceConfig;
class DhcpClient;

class NetworkManager : public IControllerHandler, public IDhcpEventHandlers {
    static NetworkManager *sInstance;

    class ControllerBinding {
        Controller      *mController;
        InterfaceConfig *mCurrentCfg;
        InterfaceConfig *mBoundCfg;

    public:
        ControllerBinding(Controller *c);
        virtual ~ControllerBinding() {}

        InterfaceConfig *getCurrentCfg() { return mCurrentCfg; }
        InterfaceConfig *getBoundCfg() { return mCurrentCfg; }
        Controller *getController() { return mController; }

        void setCurrentCfg(InterfaceConfig *cfg);
        void setBoundCfg(InterfaceConfig *cfg);
    };

    typedef android::List<ControllerBinding *> ControllerBindingCollection;

private:
    ControllerBindingCollection *mControllerBindings;
    SocketListener              *mBroadcaster;
    PropertyManager             *mPropMngr;
    DhcpClient                  *mDhcp;
    int                         mLastDhcpState;

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
    ControllerBinding *lookupBinding(Controller *c);

    void onInterfaceConnected(Controller *c);
    void onInterfaceDisconnected(Controller *c);
    void onControllerSuspending(Controller *c);
    void onControllerResumed(Controller *c);

    void onDhcpStateChanged(Controller *c, int state);
    void onDhcpEvent(Controller *c, int event);
    void onDhcpLeaseUpdated(Controller *c,
                            struct in_addr *addr, struct in_addr *net,
                            struct in_addr *brd,
                            struct in_addr *gw, struct in_addr *dns1,
                            struct in_addr *dns2);
};
#endif
