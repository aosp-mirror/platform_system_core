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

#define LOG_TAG "DhcpState"
#include <cutils/log.h>

#include "DhcpState.h"

char *DhcpState::toString(int val, char *buffer, int max) {
    if (val == DhcpState::INIT)
        strncpy(buffer, "INIT", max);
    else if (val == DhcpState::DISCOVERING)
        strncpy(buffer, "DISCOVERING", max);
    else if (val == DhcpState::REQUESTING)
        strncpy(buffer, "REQUESTING", max);
    else if (val == DhcpState::BOUND)
        strncpy(buffer, "BOUND", max);
    else if (val == DhcpState::RENEWING)
        strncpy(buffer, "RENEWING", max);
    else if (val == DhcpState::REBINDING)
        strncpy(buffer, "REBINDING", max);
    else if (val == DhcpState::REBOOT)
        strncpy(buffer, "REBOOT", max);
    else if (val == DhcpState::RENEW_REQUESTED)
        strncpy(buffer, "RENEW_REQUESTED", max);
    else if (val == DhcpState::INIT_IPV4LL)
        strncpy(buffer, "INIT_IPV4LL", max);
    else if (val == DhcpState::PROBING)
        strncpy(buffer, "PROBING", max);
    else if (val == DhcpState::ANNOUNCING)
        strncpy(buffer, "ANNOUNCING", max);
    else
        strncpy(buffer, "(internal error)", max);

    return buffer;
}

int DhcpState::parseString(const char *buffer) {
    if (!strcasecmp(buffer, "INIT"))
        return DhcpState::INIT;
    else if (!strcasecmp(buffer, "DISCOVERING"))
        return DhcpState::DISCOVERING;
    else if (!strcasecmp(buffer, "REQUESTING"))
        return DhcpState::REQUESTING;
    else if (!strcasecmp(buffer, "BOUND"))
        return DhcpState::BOUND;
    else if (!strcasecmp(buffer, "RENEWING"))
        return DhcpState::RENEWING;
    else if (!strcasecmp(buffer, "REBINDING"))
        return DhcpState::REBINDING;
    else if (!strcasecmp(buffer, "REBOOT"))
        return DhcpState::REBOOT;
    else if (!strcasecmp(buffer, "RENEW_REQUESTED"))
        return DhcpState::INIT_IPV4LL;
    else if (!strcasecmp(buffer, "INIT_IPV4LL"))
        return DhcpState::INIT_IPV4LL;
    else if (!strcasecmp(buffer, "PROBING"))
        return DhcpState::PROBING;
    else if (!strcasecmp(buffer, "ANNOUNCING"))
        return DhcpState::ANNOUNCING;
    else {
        LOGW("Bad state '%s'", buffer);
        return -1;
    }
}
