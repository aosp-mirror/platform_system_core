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

#ifndef _WIFISCANNER_H
#define _WIFISCANNER_H

#include <pthread.h>

class Supplicant;

class WifiScanner {
    pthread_t  mThread;
    int        mCtrlPipe[2];
    Supplicant *mSuppl;
    int        mPeriod;
    bool       mActive;
    

public:
    WifiScanner(Supplicant *suppl, int period);
    virtual ~WifiScanner() {}

    int getPeriod() { return mPeriod; }

    int start(bool active);
    int stop();

private:
    static void *threadStart(void *obj);

    void run();
};

#endif
