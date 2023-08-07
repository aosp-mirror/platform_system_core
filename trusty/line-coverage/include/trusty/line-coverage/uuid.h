/*
 * Copyright (C) 2023 The Android Open Source Project
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

#pragma once

#include <stdint.h>
#include <string.h>

#define UUCMP(u1, u2) if (u1 != u2) return u1 < u2

struct uuid {
    uint32_t time_low;
    uint16_t time_mid;
    uint16_t time_hi_and_version;
    uint8_t clock_seq_and_node[8];

    bool operator<(const struct uuid& rhs) const
    {
        UUCMP(time_low, rhs.time_low);
        UUCMP(time_mid, rhs.time_mid);
        UUCMP(time_hi_and_version, rhs.time_hi_and_version);
        return memcmp(clock_seq_and_node, rhs.clock_seq_and_node, 8);
    }
};
