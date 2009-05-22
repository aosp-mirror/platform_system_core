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

int NetworkManager::setProperty(const char *name, char *value) {
    char *tmp = strdup(name);
    char *next = tmp;
    char *prefix;
    char *rest;
    ControllerCollection::iterator it;

    if (!(prefix = strsep(&next, ".")))
        goto out_inval;

    rest = next;

    if (!strncasecmp(prefix, "netman", 6)) {
        errno = ENOSYS;
        return -1;
    }

    for (it = mControllers->begin(); it != mControllers->end(); ++it) {
        if (!strcasecmp(prefix, (*it)->getPropertyPrefix())) {
            return (*it)->setProperty(rest, value);
        }
    }

    errno = ENOENT;
    return -1;

out_inval:
    errno = EINVAL;
    return -1;
}

const char *NetworkManager::getProperty(const char *name, char *buffer,
                                                          size_t maxsize) {
    char *tmp = strdup(name);
    char *next = tmp;
    char *prefix;
    char *rest;
    ControllerCollection::iterator it;

    if (!(prefix = strsep(&next, ".")))
        goto out_inval;

    rest = next;

    if (!strncasecmp(prefix, "netman", 6)) {
        errno = ENOSYS;
        return NULL;
    }

    for (it = mControllers->begin(); it != mControllers->end(); ++it) {
        if (!strcasecmp(prefix, (*it)->getPropertyPrefix())) {
            return (*it)->getProperty(rest, buffer, maxsize);
        }
    }

    errno = ENOENT;
    return NULL;

out_inval:
    errno = EINVAL;
    return NULL;
}

const PropertyCollection &NetworkManager::getProperties() {
    return *mProperties;
}

int NetworkManager::onInterfaceStart(Controller *c, const InterfaceConfig *cfg) {
    LOGD("Interface %s started by controller %s", cfg->getName(), c->getName());

    // Look up the interface

    if (0) { // already started?
        errno = EADDRINUSE;
        return -1;
    }

    if (cfg->getUseDhcp()) {
    } else {
    }
    return 0;
}

int NetworkManager::onInterfaceStop(Controller *c, const char *name) {
    LOGD("Interface %s stopped by controller %s", name, c->getName());
    return 0;
}
