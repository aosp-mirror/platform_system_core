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
        strncpy(buffer, "Unknown", max);
    else if (val == SupplicantState::DISCONNECTED)
        strncpy(buffer, "Disconnected", max);
    else if (val == SupplicantState::INACTIVE)
        strncpy(buffer, "Inactive", max);
    else if (val == SupplicantState::SCANNING)
        strncpy(buffer, "Scanning", max);
    else if (val == SupplicantState::ASSOCIATING)
        strncpy(buffer, "Associating", max);
    else if (val == SupplicantState::ASSOCIATED)
        strncpy(buffer, "Associated", max);
    else if (val == SupplicantState::FOURWAY_HANDSHAKE)
        strncpy(buffer, "Fourway Handshake", max);
    else if (val == SupplicantState::GROUP_HANDSHAKE)
        strncpy(buffer, "Group Handshake", max);
    else if (val == SupplicantState::COMPLETED)
        strncpy(buffer, "Completed", max);
    else if (val == SupplicantState::IDLE)
        strncpy(buffer, "Idle", max);
    else
        strncpy(buffer, "(internal error)", max);

    return buffer;
}
