/*
 * Copyright (C) 2013-2014 The Android Open Source Project
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

#ifndef _LIBS_LOG_LOG_READ_H
#define _LIBS_LOG_LOG_READ_H

#include <time.h>

#define NS_PER_SEC 1000000000ULL
#ifdef __cplusplus
struct log_time : public timespec {
public:
    log_time(timespec &T)
    {
        tv_sec = T.tv_sec;
        tv_nsec = T.tv_nsec;
    }
    log_time(void)
    {
    }
    log_time(clockid_t id)
    {
        clock_gettime(id, (timespec *) this);
    }
    log_time(const char *T)
    {
        const uint8_t *c = (const uint8_t *) T;
        tv_sec = c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24);
        tv_nsec = c[4] | (c[5] << 8) | (c[6] << 16) | (c[7] << 24);
    }
    bool operator== (const timespec &T) const
    {
        return (tv_sec == T.tv_sec) && (tv_nsec == T.tv_nsec);
    }
    bool operator!= (const timespec &T) const
    {
        return !(*this == T);
    }
    bool operator< (const timespec &T) const
    {
        return (tv_sec < T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec < T.tv_nsec));
    }
    bool operator>= (const timespec &T) const
    {
        return !(*this < T);
    }
    bool operator> (const timespec &T) const
    {
        return (tv_sec > T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec > T.tv_nsec));
    }
    bool operator<= (const timespec &T) const
    {
        return !(*this > T);
    }
    uint64_t nsec(void) const
    {
        return static_cast<uint64_t>(tv_sec) * NS_PER_SEC + tv_nsec;
    }
};
#else
typedef struct timespec log_time;
#endif

#endif /* define _LIBS_LOG_LOG_READ_H */
