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

#ifndef _TIWLAN_WIFI_CONTROLLER_H
#define _TIWLAN_WIFI_CONTROLLER_H

#include "PropertyManager.h"
#include "WifiController.h"

class IControllerHandler;
class TiwlanEventListener;

class TiwlanWifiController : public WifiController {
    int                 mListenerSock;
    TiwlanEventListener *mEventListener;

public:
    TiwlanWifiController(PropertyManager *propmngr, IControllerHandler *handlers, char *modpath, char *modname, char *modargs);
    virtual ~TiwlanWifiController() {}

    virtual int powerUp();
    virtual int powerDown();
    virtual bool isPoweredUp();
    virtual int loadFirmware();
    virtual bool isFirmwareLoaded();

private:
    int startDriverEventListener();
};
#endif
