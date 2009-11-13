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

#ifndef _CONTROLLER_H
#define _CONTROLLER_H

#include <unistd.h>
#include <sys/types.h>

#include <utils/List.h>

class PropertyManager;
class IControllerHandler;

#include "PropertyManager.h"

class Controller {
    /*
     * Name of this controller - WIFI/VPN/USBNET/BTNET/BTDUN/LOOP/etc
     */
    char *mName;

    /*
     * Name of the system ethernet interface which this controller is
     * bound to.
     */
    char *mBoundInterface;

protected:
    PropertyManager *mPropMngr;
    IControllerHandler *mHandlers;
    
public:
    Controller(const char *name, PropertyManager *propMngr,
               IControllerHandler *handlers);
    virtual ~Controller();

    virtual int start();
    virtual int stop();

    const char *getName() { return mName; }
    const char *getBoundInterface() { return mBoundInterface; }
    
protected:
    int loadKernelModule(char *modpath, const char *args);
    bool isKernelModuleLoaded(const char *modtag);
    int unloadKernelModule(const char *modtag);
    int bindInterface(const char *ifname);
    int unbindInterface(const char *ifname);

private:
    void *loadFile(char *filename, unsigned int *_size);
};

typedef android::List<Controller *> ControllerCollection;
#endif
