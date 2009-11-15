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

#include <stdio.h>
#include <errno.h>

#define LOG_TAG "Nexus"

#include <cutils/log.h>

#include "NetworkManager.h"
#include "InterfaceConfig.h"
#include "DhcpClient.h"
#include "DhcpState.h"
#include "DhcpEvent.h"
#include "ResponseCode.h"

NetworkManager *NetworkManager::sInstance = NULL;

NetworkManager *NetworkManager::Instance() {
    if (!sInstance)
        sInstance = new NetworkManager(new PropertyManager());
    return sInstance;
}

NetworkManager::NetworkManager(PropertyManager *propMngr) {
    mBroadcaster = NULL;
    mControllerBindings = new ControllerBindingCollection();
    mPropMngr = propMngr;
    mLastDhcpState = DhcpState::INIT;
    mDhcp = new DhcpClient(this);
}

NetworkManager::~NetworkManager() {
}

int NetworkManager::run() {
    if (startControllers()) {
        LOGW("Unable to start all controllers (%s)", strerror(errno));
    }
    return 0;
}

int NetworkManager::attachController(Controller *c) {
    ControllerBinding *cb = new ControllerBinding(c);
    mControllerBindings->push_back(cb);
    return 0;
}

int NetworkManager::startControllers() {
    int rc = 0;
    ControllerBindingCollection::iterator it;

    for (it = mControllerBindings->begin(); it != mControllerBindings->end(); ++it) {
        int irc = (*it)->getController()->start();
        if (irc && !rc)
            rc = irc;
    }
    return rc;
}

int NetworkManager::stopControllers() {
    int rc = 0;
    ControllerBindingCollection::iterator it;

    for (it = mControllerBindings->begin(); it != mControllerBindings->end(); ++it) {
        int irc = (*it)->getController()->stop();
        if (irc && !rc)
            rc = irc;
    }
    return rc;
}

NetworkManager::ControllerBinding *NetworkManager::lookupBinding(Controller *c) {
    ControllerBindingCollection::iterator it;

    for (it = mControllerBindings->begin(); it != mControllerBindings->end(); ++it) {
        if ((*it)->getController() == c)
            return (*it);
    }
    errno = ENOENT;
    return NULL;
}

Controller *NetworkManager::findController(const char *name) {
    ControllerBindingCollection::iterator it;

    for (it = mControllerBindings->begin(); it != mControllerBindings->end(); ++it) {
        if (!strcasecmp((*it)->getController()->getName(), name))
            return (*it)->getController();
    }
    errno = ENOENT;
    return NULL;
}

void NetworkManager::onInterfaceConnected(Controller *c) {
    LOGD("Controller %s interface %s connected", c->getName(), c->getBoundInterface());

    if (mDhcp->start(c)) {
        LOGE("Failed to start DHCP (%s)", strerror(errno));
        return;
    }
}

void NetworkManager::onInterfaceDisconnected(Controller *c) {
    LOGD("Controller %s interface %s disconnected", c->getName(),
         c->getBoundInterface());

    mDhcp->stop();
}

void NetworkManager::onControllerSuspending(Controller *c) {
    LOGD("Controller %s interface %s suspending", c->getName(),
         c->getBoundInterface());
    mDhcp->stop();
}

void NetworkManager::onControllerResumed(Controller *c) {
    LOGD("Controller %s interface %s resumed", c->getName(),
         c->getBoundInterface());
}

void NetworkManager::onDhcpStateChanged(Controller *c, int state) {
    char tmp[255];
    char tmp2[255];

    LOGD("onDhcpStateChanged(%s -> %s)",
         DhcpState::toString(mLastDhcpState, tmp, sizeof(tmp)),
         DhcpState::toString(state, tmp2, sizeof(tmp2)));

    switch(state) {
        case DhcpState::BOUND:
            // Refresh the 'net.xxx' for the controller
            break;
        case DhcpState::RENEWING:
            break;
        default:
            break;
    }

    char *tmp3;
    asprintf(&tmp3,
             "DHCP state changed from %d (%s) -> %d (%s)", 
             mLastDhcpState,
             DhcpState::toString(mLastDhcpState, tmp, sizeof(tmp)),
             state,
             DhcpState::toString(state, tmp2, sizeof(tmp2)));

    getBroadcaster()->sendBroadcast(ResponseCode::DhcpStateChange,
                                    tmp3,
                                    false);
    free(tmp3);
                          
    mLastDhcpState = state;
}

void NetworkManager::onDhcpEvent(Controller *c, int evt) {
    char tmp[64];
    LOGD("onDhcpEvent(%s)", DhcpEvent::toString(evt, tmp, sizeof(tmp)));
}

void NetworkManager::onDhcpLeaseUpdated(Controller *c, struct in_addr *addr,
                                        struct in_addr *net,
                                        struct in_addr *brd,
                                        struct in_addr *gw,
                                        struct in_addr *dns1,
                                        struct in_addr *dns2) {
    ControllerBinding *bind = lookupBinding(c);

    if (!bind->getCurrentCfg())
        bind->setCurrentCfg(new InterfaceConfig(true));

    bind->getCurrentCfg()->setIp(addr);
    bind->getCurrentCfg()->setNetmask(net);
    bind->getCurrentCfg()->setGateway(gw);
    bind->getCurrentCfg()->setBroadcast(brd);
    bind->getCurrentCfg()->setDns(0, dns1);
    bind->getCurrentCfg()->setDns(1, dns2);
}

NetworkManager::ControllerBinding::ControllerBinding(Controller *c) :
                mController(c) {
}

void NetworkManager::ControllerBinding::setCurrentCfg(InterfaceConfig *c) {
    mCurrentCfg = c;
}

void NetworkManager::ControllerBinding::setBoundCfg(InterfaceConfig *c) {
    mBoundCfg = c;
}

