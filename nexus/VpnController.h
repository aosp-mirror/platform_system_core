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
    class VpnIntegerProperty : public IntegerProperty {
    protected:
        VpnController *mVc;
    public:
        VpnIntegerProperty(VpnController *c, const char *name, bool ro,
                            int elements);
        virtual ~VpnIntegerProperty() {}
        virtual int set(int idx, int value) = 0;
        virtual int get(int idx, int *buffer) = 0;
    };
    friend class VpnController::VpnIntegerProperty;

    class VpnStringProperty : public StringProperty {
    protected:
        VpnController *mVc;
    public:
        VpnStringProperty(VpnController *c, const char *name, bool ro,
                            int elements);
        virtual ~VpnStringProperty() {}
        virtual int set(int idx, const char *value) = 0;
        virtual int get(int idx, char *buffer, size_t max) = 0;
    };
    friend class VpnController::VpnStringProperty;

    class VpnIPV4AddressProperty : public IPV4AddressProperty {
    protected:
        VpnController *mVc;
    public:
        VpnIPV4AddressProperty(VpnController *c, const char *name, bool ro,
                          int elements);
        virtual ~VpnIPV4AddressProperty() {}
        virtual int set(int idx, struct in_addr *value) = 0;
        virtual int get(int idx, struct in_addr *buffer) = 0;
    };
    friend class VpnController::VpnIPV4AddressProperty;

    class VpnEnabledProperty : public VpnIntegerProperty {
    public:
        VpnEnabledProperty(VpnController *c);
        virtual ~VpnEnabledProperty() {};
        int set(int idx, int value);
        int get(int idx, int *buffer);
    };

    bool           mEnabled;
    /*
     * Gateway of the VPN server to connect to
     */
    struct in_addr mGateway;

    struct {
        VpnEnabledProperty *propEnabled;
    } mStaticProperties;

    struct {
        IPV4AddressPropertyHelper *propGateway;
    } mDynamicProperties;

public:
    VpnController(PropertyManager *propmngr, IControllerHandler *handlers);
    virtual ~VpnController() {}

    virtual int start();
    virtual int stop();

protected:
    virtual int enable() = 0;
    virtual int disable() = 0;
};

#endif
