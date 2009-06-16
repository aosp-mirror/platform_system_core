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

#ifndef _VPN_CONTROLLER_H
#define _VPN_CONTROLLER_H

#include <netinet/in.h>

#include "Controller.h"

class IControllerHandler;

class VpnController : public Controller {
    bool           mEnabled;
    /*
     * Gateway of the VPN server to connect to
     */
    struct in_addr mVpnGateway;

public:
    VpnController(PropertyManager *propmngr, IControllerHandler *handlers);
    virtual ~VpnController() {}

    virtual int start();
    virtual int stop();

    virtual int set(const char *name, const char *value);
    virtual const char *get(const char *name, char *buffer, size_t maxlen);

protected:
    virtual int enable() = 0;
    virtual int disable() = 0;

};

#endif
