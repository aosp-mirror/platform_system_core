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

#define LOG_TAG "SupplicantState"
#include <cutils/log.h>

#include "SupplicantState.h"

char *SupplicantState::toString(int val, char *buffer, int max) {
    if (val == SupplicantState::UNKNOWN)
        strncpy(buffer, "UNKNOWN", max);
    else if (val == SupplicantState::DISCONNECTED)
        strncpy(buffer, "DISCONNECTED", max);
    else if (val == SupplicantState::INACTIVE)
        strncpy(buffer, "INACTIVE", max);
    else if (val == SupplicantState::SCANNING)
        strncpy(buffer, "SCANNING", max);
    else if (val == SupplicantState::ASSOCIATING)
        strncpy(buffer, "ASSOCIATING", max);
    else if (val == SupplicantState::ASSOCIATED)
        strncpy(buffer, "ASSOCIATED", max);
    else if (val == SupplicantState::FOURWAY_HANDSHAKE)
        strncpy(buffer, "FOURWAY_HANDSHAKE", max);
    else if (val == SupplicantState::GROUP_HANDSHAKE)
        strncpy(buffer, "GROUP_HANDSHAKE", max);
    else if (val == SupplicantState::COMPLETED)
        strncpy(buffer, "COMPLETED", max);
    else if (val == SupplicantState::IDLE)
        strncpy(buffer, "IDLE", max);
    else
        strncpy(buffer, "(internal error)", max);

    return buffer;
}
