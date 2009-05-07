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
#ifndef _FRAMEWORKMANAGER_H
#define _FRAMEWORKMANAGER_H

#include <pthread.h>

class FrameworkListener;

class FrameworkManager {
    int mDoorbell;        // Socket used to accept connections from framework
    int mFwSock;          // Socket used to communicate with framework
    const char *mSocketName;

    FrameworkListener *mListener;
    
    pthread_mutex_t mWriteMutex;

public:
    FrameworkManager(FrameworkListener *Listener);
    virtual ~FrameworkManager() {}

    int run();
    int sendMsg(char *msg);
    int sendMsg(char *msg, char *data);
};
#endif
