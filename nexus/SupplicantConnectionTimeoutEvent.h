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

#ifndef _SupplicantConnectionTimeoutEvent_H
#define _SupplicantConnectionTimeoutEvent_H

#include "SupplicantEvent.h"

class SupplicantConnectionTimeoutEvent : public SupplicantEvent {
private:
    char *mBssid;
    bool mReassociated;

public:
    SupplicantConnectionTimeoutEvent(int level, char *event, size_t len);
    virtual ~SupplicantConnectionTimeoutEvent();

    const char *getBssid() { return mBssid; }
};

#endif
