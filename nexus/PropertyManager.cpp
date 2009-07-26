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

#define LOG_TAG "PropertyManager"

#include <cutils/log.h>

#include "PropertyManager.h"

PropertyManager::PropertyManager() {
    mPropertyPairs = new PropertyPairCollection();
    pthread_mutex_init(&mLock, NULL);
}

PropertyManager::~PropertyManager() {
    delete mPropertyPairs;
}

int PropertyManager::registerProperty(const char *name, IPropertyProvider *pp) {
    PropertyPairCollection::iterator it;

//    LOGD("registerProperty(%s)", name);
    pthread_mutex_lock(&mLock);
    for (it = mPropertyPairs->begin(); it != mPropertyPairs->end(); ++it) {
        if (!strcmp(name, (*it)->getName())) {
            errno = EADDRINUSE;
            LOGE("Failed to register property %s (%s)",
                 name, strerror(errno));
            pthread_mutex_unlock(&mLock);
            return -1;
        }
    }
    mPropertyPairs->push_back(new PropertyPair(name, pp));
    pthread_mutex_unlock(&mLock);
    return 0;
}

int PropertyManager::unregisterProperty(const char *name) {
    PropertyPairCollection::iterator it;

//    LOGD("unregisterProperty(%s)", name);
    pthread_mutex_lock(&mLock);
    for (it = mPropertyPairs->begin(); it != mPropertyPairs->end(); ++it) {
        if (!strcmp(name, (*it)->getName())) {
            delete ((*it));
            mPropertyPairs->erase(it);
            pthread_mutex_unlock(&mLock);
            return 0;
        }
    }
    pthread_mutex_unlock(&mLock);
    errno = ENOENT;
    return -1;
}

/*
 * IPropertyManager methods
 */

int PropertyManager::set(const char *name, const char *value) {
    PropertyPairCollection::iterator it;

    pthread_mutex_lock(&mLock);
    for (it = mPropertyPairs->begin(); it != mPropertyPairs->end(); ++it) {
        if (!strcmp(name, (*it)->getName())) {
            pthread_mutex_unlock(&mLock);
            return (*it)->getProvider()->set(name, value);
        }
    }
    pthread_mutex_unlock(&mLock);
    errno = ENOENT;
    return -1;
}

const char *PropertyManager::get(const char *name, char *buffer, size_t max) {
    PropertyPairCollection::iterator it;

    memset(buffer, 0, max);
    pthread_mutex_lock(&mLock);
    for (it = mPropertyPairs->begin(); it != mPropertyPairs->end(); ++it) {
        if (!strcmp(name, (*it)->getName())) {
            pthread_mutex_unlock(&mLock);
            return (*it)->getProvider()->get(name, buffer, max);
            }
    }
    pthread_mutex_unlock(&mLock);
    errno = ENOENT;
    return NULL;
}

android::List<char *> *PropertyManager::createPropertyList() {
    android::List<char *> *c = new android::List<char *>();

    PropertyPairCollection::iterator it;

    pthread_mutex_lock(&mLock);
    for (it = mPropertyPairs->begin(); it != mPropertyPairs->end(); ++it)
         c->push_back(strdup((*it)->getName()));
    pthread_mutex_unlock(&mLock);
    return c;
}

PropertyPair::PropertyPair(const char *name, IPropertyProvider *pp) {
    mName = strdup(name);
    mPp = pp;
}

PropertyPair::~PropertyPair() {
    free(mName);
}
