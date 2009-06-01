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
#include "PropertyCollection.h"

class InterfaceConfig;

class NetworkManager {
private:
    static NetworkManager *sInstance;

private:
    ControllerCollection *mControllers;
    SocketListener       *mBroadcaster;
    PropertyCollection   *mProperties;

public:
    virtual ~NetworkManager() {}

    int run();

    int attachController(Controller *controller);

    Controller *findController(const char *name);

    const PropertyCollection &getProperties();
    int setProperty(const char *name, char *value);
    const char *getProperty(const char *name, char *buffer, size_t maxsize);

    void setBroadcaster(SocketListener *sl) { mBroadcaster = sl; }
    SocketListener *getBroadcaster() { return mBroadcaster; }

    static NetworkManager *Instance();

private:
    int startControllers();
    int stopControllers();
    int registerProperty(const char *name);
    int unregisterProperty(const char *name);

    NetworkManager();

public:
    /*
     * Called from a controller when an interface is available/ready for use.
     * 'cfg' contains information on how this interface should be configured.
     */
    int onInterfaceStart(Controller *c, const InterfaceConfig *cfg);

    /*
     * Called from a controller when an interface should be shut down
     */
    int onInterfaceStop(Controller *c, const char *name);
};
#endif
