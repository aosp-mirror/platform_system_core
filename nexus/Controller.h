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
#ifndef _CONTROLLER_H
#define _CONTROLLER_H

#include <unistd.h>
#include <sys/types.h>

#include "../../../frameworks/base/include/utils/List.h"

#include "PropertyCollection.h"

class Controller {
private:
    const char *mName;
    const char *mPropertyPrefix;
    PropertyCollection *mProperties;
    bool mEnabled;
    
public:
    Controller(const char *name, const char *prefix);
    virtual ~Controller() {}

    virtual int start();
    virtual int stop();

    virtual const PropertyCollection &getProperties();
    virtual int setProperty(const char *name, char *value);
    virtual const char *getProperty(const char *name, char *buffer, size_t maxsize);

    const char *getName() { return mName; }
    const char *getPropertyPrefix() { return mPropertyPrefix; }

protected:
    int loadKernelModule(char *modpath, const char *args);
    bool isKernelModuleLoaded(const char *modtag);
    int unloadKernelModule(const char *modtag);

    int registerProperty(const char *name);
    int unregisterProperty(const char *name);

private:
    void *loadFile(char *filename, unsigned int *_size);

    virtual int enable() = 0;
    virtual int disable() = 0;

};

typedef android::List<Controller *> ControllerCollection;
#endif
