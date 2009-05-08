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

#include "Controller.h"

#include <sysutils/FrameworkManager.h>

class NetworkManager {
private:
    FrameworkListener    *mListener;
    FrameworkManager     *mFm;
    ControllerCollection *mControllers;

public:
    NetworkManager();
    virtual ~NetworkManager() {}

    int run();

private:
    void addController(Controller *c);
    int startControllers();
    int stopControllers();

public:
    Controller *findController(const char *name);
    ControllerCollection *getControllers() { return mControllers; }
    FrameworkManager *getFrameworkManager() { return mFm; }

public:
// XXX: Extract these into an interface
    int onInterfaceCreated(Controller *c, char *name);
    int onInterfaceDestroyed(Controller *c, char *name);

};
#endif
