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

#ifndef _PROPERTY_H
#define _PROPERTY_H

#include <netinet/in.h>
#include <utils/List.h>

class Property {
    const char *mName;
    bool       mReadOnly;
    int        mType;
    int        mNumElements;

public:
    static const int NameMaxSize   = 128;
    static const int ValueMaxSize  = 255;

    static const int Type_STRING  = 1;
    static const int Type_INTEGER = 2;
    static const int Type_IPV4    = 3;

    Property(const char *name, bool ro, int type, int elements);
    virtual ~Property() {}

    virtual int set(int idx, const char *value) = 0;
    virtual int set(int idx, int value) = 0;
    virtual int set(int idx, struct in_addr *value) = 0;

    virtual int get(int idx, char *buffer, size_t max) = 0;
    virtual int get(int idx, int *buffer) = 0;
    virtual int get(int idx, struct in_addr *buffer) = 0;

    int getType() { return mType; }
    bool getReadOnly() { return mReadOnly; }
    int getNumElements() { return mNumElements; }
    const char *getName() { return mName; }
};

class StringProperty : public Property {
public:
    StringProperty(const char *name, bool ro, int elements);
    virtual ~StringProperty() {}
 
    virtual int set(int idx, const char *value) = 0;
    int set(int idx, int value);
    int set(int idx, struct in_addr *value);

    virtual int get(int idx, char *buffer, size_t max) = 0;
    int get(int idx, int *buffer);
    int get(int idx, struct in_addr *buffer);
};

class StringPropertyHelper : public StringProperty {
    char *mBuffer;
    size_t mMax;
public:
    StringPropertyHelper(const char *name, bool ro,
                         char *buffer, size_t max);
    int set(int idx, const char *value);
    int get(int idx, char *buffer, size_t max);
};

class IntegerProperty : public Property {
public:
    IntegerProperty(const char *name, bool ro, int elements);
    virtual ~IntegerProperty() {}
 
    int set(int idx, const char *value);
    virtual int set(int idx, int value) = 0;
    int set(int idx, struct in_addr *value);

    int get(int idx, char *buffer, size_t max);
    virtual int get(int idx, int *buffer) = 0;
    int get(int idx, struct in_addr *buffer);
};

class IntegerPropertyHelper : public IntegerProperty {
    int *mBuffer;
public:
    IntegerPropertyHelper(const char *name, bool ro, int *buffer);
    int set(int idx, int value);
    int get(int idx, int *buffer);
};

class IPV4AddressProperty : public Property {
public:
    IPV4AddressProperty(const char *name, bool ro, int elements);
    virtual ~IPV4AddressProperty() {}
 
    int set(int idx, const char *value);
    int set(int idx, int value);
    virtual int set(int idx, struct in_addr *value) = 0;

    int get(int idx, char *buffer, size_t max);
    int get(int idx, int *buffer);
    virtual int get(int idx, struct in_addr *buffer) = 0;
};

class IPV4AddressPropertyHelper : public IPV4AddressProperty {
    struct in_addr *mBuffer;
public:
    IPV4AddressPropertyHelper(const char *name, bool ro, struct in_addr *buf);
    int set(int idx, struct in_addr *value);
    int get(int idx, struct in_addr *buffer);
};

typedef android::List<Property *> PropertyCollection;

class PropertyNamespace {
    char         *mName;
    PropertyCollection *mProperties;

public:
    PropertyNamespace(const char *name);
    virtual ~PropertyNamespace();

    const char *getName() { return mName; }
    PropertyCollection *getProperties() { return mProperties; }
};

typedef android::List<PropertyNamespace *> PropertyNamespaceCollection;
#endif
