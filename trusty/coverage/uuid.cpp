/*
 * Copyright (C) 2021 The Android Open Sourete Project
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

#include <string.h>
#include <trusty/coverage/uuid.h>
#include <uuid.h>

#include <stdio.h>

static uint16_t reverse_u16(uint16_t u) {
    return u << 8 | u >> 8;
}

static uint32_t reverse_u32(uint32_t u) {
    return reverse_u16((uint16_t)u) << 16 | reverse_u16(u >> 16);
}

bool str_to_uuid(const char* str, struct uuid* uuid) {
    uuid_t uu;
    static_assert(sizeof(uu) == sizeof(*uuid));

    if (uuid_parse(str, uu)) {
        return false;
    }

    memcpy(uuid, uu, sizeof(*uuid));
    uuid->time_low = reverse_u32(uuid->time_low);
    uuid->time_mid = reverse_u16(uuid->time_mid);
    uuid->time_hi_and_version = reverse_u16(uuid->time_hi_and_version);
    return true;
}
