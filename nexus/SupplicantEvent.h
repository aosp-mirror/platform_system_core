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

#ifndef _SUPPLICANT_EVENT_H
#define _SUPPLICANT_EVENT_H

#include <sys/types.h>

class SupplicantEvent {
private:
    int mType;
    int mLevel;

public:
    static const int EVENT_UNKNOWN           = 0;
    static const int EVENT_CONNECTED         = 1;
    static const int EVENT_DISCONNECTED      = 2;
    static const int EVENT_TERMINATING       = 3;
    static const int EVENT_PASSWORD_CHANGED  = 4;
    static const int EVENT_EAP_NOTIFICATION  = 5;
    static const int EVENT_EAP_STARTED       = 6;
    static const int EVENT_EAP_METHOD        = 7;
    static const int EVENT_EAP_SUCCESS       = 8;
    static const int EVENT_EAP_FAILURE       = 9;
    static const int EVENT_SCAN_RESULTS      = 10;
    static const int EVENT_STATE_CHANGE      = 11;
    static const int EVENT_LINK_SPEED        = 12;
    static const int EVENT_DRIVER_STATE      = 13;
    static const int EVENT_ASSOCIATING       = 14;
    static const int EVENT_ASSOCIATED        = 15;
    static const int EVENT_CONNECTIONTIMEOUT = 16;

public:
    SupplicantEvent(int type, int level);
    virtual ~SupplicantEvent() {}

    int getType() { return mType; }
    int getLevel() { return mLevel; }
};

#endif
