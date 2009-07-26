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

#define LOG_TAG "SupplicantStateChangeEvent"
#include <cutils/log.h>

#include "SupplicantStateChangeEvent.h"

SupplicantStateChangeEvent::SupplicantStateChangeEvent(int level, char *event,
                                                       size_t len) :
                            SupplicantEvent(SupplicantEvent::EVENT_STATE_CHANGE,
                                            level) {
    // XXX: move this stuff into a static creation method
    char *p = index(event, ' ');
    if (!p) {
        LOGW("Bad event '%s'\n", event);
        return;
    }

    mState = atoi(p + strlen("state=") + 1);
}

SupplicantStateChangeEvent::SupplicantStateChangeEvent(int state) :
                            SupplicantEvent(SupplicantEvent::EVENT_STATE_CHANGE, -1) {
    mState = state;
}

SupplicantStateChangeEvent::~SupplicantStateChangeEvent() {
}

