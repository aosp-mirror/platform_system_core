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

#ifndef _LOGD_LOG_UTILS_H__
#define _LOGD_LOG_UTILS_H__

#include <sys/types.h>

#include <log/log.h>
#include <sysutils/SocketClient.h>

// Hijack this header as a common include file used by most all sources
// to report some utilities defined here and there.

namespace android {

// Furnished in main.cpp. Caller must own and free returned value
char *uidToName(uid_t uid);

// Furnished in LogStatistics.cpp. Caller must own and free returned value
char *pidToName(pid_t pid);
char *tidToName(pid_t tid);

// Furnished in main.cpp. Thread safe.
const char *tagToName(uint32_t tag);

}

// Furnished in LogCommand.cpp
bool clientHasLogCredentials(uid_t uid, gid_t gid, pid_t pid);
bool clientHasLogCredentials(SocketClient *cli);

// Furnished in main.cpp
#define BOOL_DEFAULT_FLAG_TRUE_FALSE 0x1
#define BOOL_DEFAULT_FALSE       0x0     // false if property not present
#define BOOL_DEFAULT_TRUE        0x1     // true if property not present
#define BOOL_DEFAULT_FLAG_PERSIST    0x2 // <key>, persist.<key>, ro.<key>
#define BOOL_DEFAULT_FLAG_ENG        0x4 // off for user
#define BOOL_DEFAULT_FLAG_SVELTE     0x8 // off for low_ram

bool property_get_bool(const char *key, int def);

static inline bool worstUidEnabledForLogid(log_id_t id) {
    return (id == LOG_ID_MAIN) || (id == LOG_ID_SYSTEM) || (id == LOG_ID_RADIO);
}

template <int (*cmp)(const char *l, const char *r, const size_t s)>
static inline int fast(const char *l, const char *r, const size_t s) {
    return (*l != *r) || cmp(l + 1, r + 1, s - 1);
}

template <int (*cmp)(const void *l, const void *r, const size_t s)>
static inline int fast(const void *lv, const void *rv, const size_t s) {
    const char *l = static_cast<const char *>(lv);
    const char *r = static_cast<const char *>(rv);
    return (*l != *r) || cmp(l + 1, r + 1, s - 1);
}

template <int (*cmp)(const char *l, const char *r)>
static inline int fast(const char *l, const char *r) {
    return (*l != *r) || cmp(l + 1, r + 1);
}

#endif // _LOGD_LOG_UTILS_H__
