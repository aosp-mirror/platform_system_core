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

#include <stdlib.h>
#include <errno.h>
#include <strings.h>
#include <netinet/in.h>

#define LOG_TAG "Property"

#include <cutils/log.h>

#include "Property.h"

Property::Property(const char *name, bool readOnly,
                   int type, int numElements) :
          mName(name), mReadOnly(readOnly), mType(type),
          mNumElements(numElements) {
    if (index(name, '.')) {
        LOGW("Property name %s violates namespace rules", name);
    }
}

StringProperty::StringProperty(const char *name, bool ro, int elements) :
                Property(name, ro, Property::Type_STRING, elements) {
}
int StringProperty::set(int idx, int value) {
    LOGE("Integer 'set' called on string property!");
    errno = EINVAL;
    return -1;
}
int StringProperty::set(int idx, struct in_addr *value) {
    LOGE("IpAddr 'set' called on string property!");
    errno = EINVAL;
    return -1;
}
int StringProperty::get(int idx, int *buffer) {
    LOGE("Integer 'get' called on string property!");
    errno = EINVAL;
    return -1;
}
int StringProperty::get(int idx, struct in_addr *buffer) {
    LOGE("IpAddr 'get' called on string property!");
    errno = EINVAL;
    return -1;
}

StringPropertyHelper::StringPropertyHelper(const char *name, bool ro,
                                           char *buffer, size_t max) :
                      StringProperty(name, ro, 1) {
    mBuffer = buffer;
    mMax = max;
}

int StringPropertyHelper::set(int idx, const char *value) {
    if (idx != 0) {
        LOGW("Attempt to use array index on StringPropertyHelper::set");
        errno = EINVAL;
        return -1;
    }
    strncpy(mBuffer, value, mMax);
    return 0;
}

int StringPropertyHelper::get(int idx, char *buffer, size_t max) {
    if (idx != 0) {
        LOGW("Attempt to use array index on StringPropertyHelper::get");
        errno = EINVAL;
        return -1;
    }
    strncpy(buffer, mBuffer, max);
    return 0;
}
 
IntegerProperty::IntegerProperty(const char *name, bool ro, int elements) :
                Property(name, ro, Property::Type_INTEGER, elements) {
}

int IntegerProperty::set(int idx, const char *value) {
    LOGE("String 'set' called on integer property!");
    errno = EINVAL;
    return -1;
}
int IntegerProperty::set(int idx, struct in_addr *value) {
    LOGE("IpAddr 'set' called on integer property!");
    errno = EINVAL;
    return -1;
}
int IntegerProperty::get(int idx, char *buffer, size_t max) {
    LOGE("String 'get' called on integer property!");
    errno = EINVAL;
    return -1;
}
int IntegerProperty::get(int idx, struct in_addr *buffer) {
    LOGE("IpAddr 'get' called on integer property!");
    errno = EINVAL;
    return -1;
}

IntegerPropertyHelper::IntegerPropertyHelper(const char *name, bool ro,
                                             int *buffer) :
                       IntegerProperty(name, ro, 1) {
    mBuffer = buffer;
}

int IntegerPropertyHelper::set(int idx, int value) {
    if (idx != 0) {
        LOGW("Attempt to use array index on IntegerPropertyHelper::set");
        errno = EINVAL;
        return -1;
    }
    *mBuffer = value;
    return 0;
}

int IntegerPropertyHelper::get(int idx, int *buffer) {
    if (idx != 0) {
        LOGW("Attempt to use array index on IntegerPropertyHelper::get");
        errno = EINVAL;
        return -1;
    }
    *buffer = *mBuffer;
    return 0;
}

IPV4AddressProperty::IPV4AddressProperty(const char *name, bool ro, int elements) :
                Property(name, ro, Property::Type_IPV4, elements) {
}

int IPV4AddressProperty::set(int idx, const char *value) {
    LOGE("String 'set' called on ipv4 property!");
    errno = EINVAL;
    return -1;
}
int IPV4AddressProperty::set(int idx, int value) {
    LOGE("Integer 'set' called on ipv4 property!");
    errno = EINVAL;
    return -1;
}
int IPV4AddressProperty::get(int idx, char *buffer, size_t max) {
    LOGE("String 'get' called on ipv4 property!");
    errno = EINVAL;
    return -1;
}
int IPV4AddressProperty::get(int idx, int *buffer) {
    LOGE("Integer 'get' called on ipv4 property!");
    errno = EINVAL;
    return -1;
}

IPV4AddressPropertyHelper::IPV4AddressPropertyHelper(const char *name, bool ro,
                                                     struct in_addr *buffer) :
                       IPV4AddressProperty(name, ro, 1) {
    mBuffer = buffer;
}

int IPV4AddressPropertyHelper::set(int idx, struct in_addr *value) {
    if (idx != 0) {
        LOGW("Attempt to use array index on IPV4AddressPropertyHelper::set");
        errno = EINVAL;
        return -1;
    }
    memcpy(mBuffer, value, sizeof(struct in_addr));
    return 0;
}

int IPV4AddressPropertyHelper::get(int idx, struct in_addr *buffer) {
    if (idx != 0) {
        LOGW("Attempt to use array index on IPV4AddressPropertyHelper::get");
        errno = EINVAL;
        return -1;
    }
    memcpy(buffer, mBuffer, sizeof(struct in_addr));
    return 0;
}

PropertyNamespace::PropertyNamespace(const char *name) {
    mName = strdup(name);
    mProperties = new PropertyCollection();
}

PropertyNamespace::~PropertyNamespace() {
    PropertyCollection::iterator it;
    for (it = mProperties->begin(); it != mProperties->end();) {
        delete (*it);
        it = mProperties->erase(it);
    }
    delete mProperties;
    free(mName);
}
