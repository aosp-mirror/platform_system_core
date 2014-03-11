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

/* struct log_time is a wire-format variant of struct timespec */
#define NS_PER_SEC 1000000000ULL
#ifdef __cplusplus
struct log_time {
public:
    uint32_t tv_sec; // good to Feb 5 2106
    uint32_t tv_nsec;

    log_time(const timespec &T)
    {
        tv_sec = T.tv_sec;
        tv_nsec = T.tv_nsec;
    }
    log_time(const log_time &T)
    {
        tv_sec = T.tv_sec;
        tv_nsec = T.tv_nsec;
    }
    log_time(uint32_t sec, uint32_t nsec)
    {
        tv_sec = sec;
        tv_nsec = nsec;
    }
    log_time()
    {
    }
    log_time(clockid_t id)
    {
        timespec T;
        clock_gettime(id, &T);
        tv_sec = T.tv_sec;
        tv_nsec = T.tv_nsec;
    }
    log_time(const char *T)
    {
        const uint8_t *c = (const uint8_t *) T;
        tv_sec = c[0] | (c[1] << 8) | (c[2] << 16) | (c[3] << 24);
        tv_nsec = c[4] | (c[5] << 8) | (c[6] << 16) | (c[7] << 24);
    }

    // timespec
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

    // log_time
    bool operator== (const log_time &T) const
    {
        return (tv_sec == T.tv_sec) && (tv_nsec == T.tv_nsec);
    }
    bool operator!= (const log_time &T) const
    {
        return !(*this == T);
    }
    bool operator< (const log_time &T) const
    {
        return (tv_sec < T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec < T.tv_nsec));
    }
    bool operator>= (const log_time &T) const
    {
        return !(*this < T);
    }
    bool operator> (const log_time &T) const
    {
        return (tv_sec > T.tv_sec)
            || ((tv_sec == T.tv_sec) && (tv_nsec > T.tv_nsec));
    }
    bool operator<= (const log_time &T) const
    {
        return !(*this > T);
    }

    uint64_t nsec() const
    {
        return static_cast<uint64_t>(tv_sec) * NS_PER_SEC + tv_nsec;
    }
} __attribute__((__packed__));
#else
typedef struct log_time {
    uint32_t tv_sec;
    uint32_t tv_nsec;
} __attribute__((__packed__)) log_time;
#endif

#endif /* define _LIBS_LOG_LOG_READ_H */
