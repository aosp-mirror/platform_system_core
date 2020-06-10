/*
 * Copyright (C) 2012-2015 The Android Open Source Project
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

#include <sys/cdefs.h>
#include <sys/types.h>

#include <private/android_logger.h>
#include <sysutils/SocketClient.h>
#include <utils/FastStrcmp.h>

// Hijack this header as a common include file used by most all sources
// to report some utilities defined here and there.

namespace android {

// Furnished in main.cpp. Caller must own and free returned value
char* uidToName(uid_t uid);

// Caller must own and free returned value
char* pidToName(pid_t pid);
char* tidToName(pid_t tid);

// Furnished in LogTags.cpp. Thread safe.
const char* tagToName(uint32_t tag);

// Furnished by LogKlog.cpp
char* log_strntok_r(char* s, ssize_t& len, char*& saveptr, ssize_t& sublen);

// needle should reference a string longer than 1 character
static inline const char* strnstr(const char* s, ssize_t len,
                                  const char* needle) {
    if (len <= 0) return nullptr;

    const char c = *needle++;
    const size_t needleLen = strlen(needle);
    do {
        do {
            if (len <= (ssize_t)needleLen) return nullptr;
            --len;
        } while (*s++ != c);
    } while (fastcmp<memcmp>(s, needle, needleLen));
    s--;
    return s;
}
}

// Returns true if the log buffer is meant for binary logs.
static inline bool IsBinary(log_id_t log_id) {
    return log_id == LOG_ID_EVENTS || log_id == LOG_ID_STATS || log_id == LOG_ID_SECURITY;
}

// Returns the numeric log tag for binary log messages.
static inline uint32_t MsgToTag(const char* msg, uint16_t msg_len) {
    if (msg_len < sizeof(android_event_header_t)) {
        return 0;
    }

    return reinterpret_cast<const android_event_header_t*>(msg)->tag;
}

static inline bool worstUidEnabledForLogid(log_id_t id) {
    return (id == LOG_ID_MAIN) || (id == LOG_ID_SYSTEM) ||
           (id == LOG_ID_RADIO) || (id == LOG_ID_EVENTS);
}
