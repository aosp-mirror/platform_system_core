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

NetworkManager *NetworkManager::sInstance = NULL;

NetworkManager *NetworkManager::Instance() {
    if (!sInstance)
        sInstance = new NetworkManager();
    return sInstance;
}

NetworkManager::NetworkManager() {
    mBroadcaster = NULL;
    mControllers = new ControllerCollection();
}

int NetworkManager::run() {
    if (startControllers()) {
        LOGW("Unable to start all controllers (%s)", strerror(errno));
    }
    return 0;
}

int NetworkManager::attachController(Controller *c) {
    mControllers->push_back(c);
    return 0;
}

int NetworkManager::startControllers() {
    int rc = 0;
    ControllerCollection::iterator i;

    for (i = mControllers->begin(); i != mControllers->end(); ++i) {
        int irc = (*i)->start();
        LOGD("Controller '%s' start rc = %d", (*i)->getName(), irc);
        if (irc && !rc) 
            rc = irc;
    }
    return rc;
}

int NetworkManager::stopControllers() {
    int rc = 0;
    ControllerCollection::iterator i;

    for (i = mControllers->begin(); i != mControllers->end(); ++i) {
        int irc = (*i)->stop();
        LOGD("Controller '%s' stop rc = %d", (*i)->getName(), irc);
        if (irc && !rc) 
            rc = irc;
    }
    return rc;
}

Controller *NetworkManager::findController(const char *name) {
    ControllerCollection::iterator i;
    for (i = mControllers->begin(); i != mControllers->end(); ++i) {
        if (!strcmp((*i)->getName(), name))
            return *i;
    }
    LOGW("Controller '%s' not found", name);
    return NULL;
}

int NetworkManager::onInterfaceCreated(Controller *c, char *name) {
    LOGD("Interface %s created by controller %s", name, c->getName());
    return 0;
}

int NetworkManager::onInterfaceDestroyed(Controller *c, char *name) {
    LOGD("Interface %s destroyed by controller %s", name, c->getName());
    return 0;
}
