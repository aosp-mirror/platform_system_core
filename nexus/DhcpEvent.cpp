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

#include <stdio.h>

#define LOG_TAG "DhcpEvent"
#include <cutils/log.h>

#include "DhcpEvent.h"

char *DhcpEvent::toString(int val, char *buffer, int max) {
    if (val == DhcpEvent::UNKNOWN)
        strncpy(buffer, "UNKNOWN", max);
    else if (val == DhcpEvent::STOP)
        strncpy(buffer, "STOP", max);
    else if (val == DhcpEvent::RENEW)
        strncpy(buffer, "RENEW", max);
    else if (val == DhcpEvent::RELEASE)
        strncpy(buffer, "RELEASE", max);
    else if (val == DhcpEvent::TIMEOUT)
        strncpy(buffer, "TIMEOUT", max);
    else
        strncpy(buffer, "(internal error)", max);

    return buffer;
}

int DhcpEvent::parseString(const char *buffer) {
    if (!strcasecmp(buffer, "UNKNOWN"))
        return DhcpEvent::UNKNOWN;
    else if (!strcasecmp(buffer, "STOP"))
        return DhcpEvent::STOP;
    else if (!strcasecmp(buffer, "RENEW"))
        return DhcpEvent::RENEW;
    else if (!strcasecmp(buffer, "RELEASE"))
        return DhcpEvent::RELEASE;
    else if (!strcasecmp(buffer, "TIMEOUT"))
        return DhcpEvent::TIMEOUT;
    else {
        LOGW("Bad event '%s'", buffer);
        return -1;
    }
}
