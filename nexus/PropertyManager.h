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

#ifndef _PROPERTY_MANAGER_H
#define _PROPERTY_MANAGER_H

#include <errno.h>
#include <pthread.h>

#include <utils/List.h>

#include "IPropertyProvider.h"

class PropertyPair {
private:
    char *mName;
    IPropertyProvider *mPp;
 
public:
    PropertyPair(const char *name, IPropertyProvider *pp);
    virtual ~PropertyPair();

    const char *getName() { return mName; }
    IPropertyProvider *getProvider() { return mPp; }
};

typedef android::List<PropertyPair *> PropertyPairCollection;

class PropertyManager {
    PropertyPairCollection *mPropertyPairs;
    pthread_mutex_t         mLock;

public:
    PropertyManager();
    virtual ~PropertyManager();   
    int registerProperty(const char *name, IPropertyProvider *pp);
    int unregisterProperty(const char *name);
    android::List<char *> *createPropertyList();

    int set(const char *name, const char *value);
    const char *get(const char *name, char *buffer, size_t max);
};

#endif
