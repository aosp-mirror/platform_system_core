/*
 * Copyright (C) 2014 The Android Open Source Project
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

#ifndef __ADB_TRACE_H
#define __ADB_TRACE_H

#if !ADB_HOST
#include <android/log.h>
#else
#include <stdio.h>
#endif

/* IMPORTANT: if you change the following list, don't
 * forget to update the corresponding 'tags' table in
 * the adb_trace_init() function implemented in adb.c
 */
enum AdbTrace {
    TRACE_ADB = 0,   /* 0x001 */
    TRACE_SOCKETS,
    TRACE_PACKETS,
    TRACE_TRANSPORT,
    TRACE_RWX,       /* 0x010 */
    TRACE_USB,
    TRACE_SYNC,
    TRACE_SYSDEPS,
    TRACE_JDWP,      /* 0x100 */
    TRACE_SERVICES,
    TRACE_AUTH,
    TRACE_FDEVENT,
};

extern int adb_trace_mask;
extern unsigned char adb_trace_output_count;
void adb_trace_init(char**);

#  define ADB_TRACING  ((adb_trace_mask & (1 << TRACE_TAG)) != 0)

/* you must define TRACE_TAG before using this macro */
#if ADB_HOST
#  define D(fmt, ...) \
        do { \
            if (ADB_TRACING) { \
                int saved_errno = errno; \
                adb_mutex_lock(&D_lock); \
                errno = saved_errno; \
                fprintf(stderr, "%5d:%5lu %s | " fmt, \
                        getpid(), adb_thread_id(), __FUNCTION__, ## __VA_ARGS__); \
                fflush(stderr); \
                adb_mutex_unlock(&D_lock); \
                errno = saved_errno; \
           } \
        } while (0)
#  define DR(...) \
        do { \
            if (ADB_TRACING) { \
                int saved_errno = errno; \
                adb_mutex_lock(&D_lock); \
                errno = saved_errno; \
                fprintf(stderr, __VA_ARGS__); \
                fflush(stderr); \
                adb_mutex_unlock(&D_lock); \
                errno = saved_errno; \
           } \
        } while (0)
#else
#  define D(...) \
        do { \
            if (ADB_TRACING) { \
                __android_log_print(ANDROID_LOG_INFO, __FUNCTION__, __VA_ARGS__); \
            } \
        } while (0)
#  define DR(...) \
        do { \
            if (ADB_TRACING) { \
                __android_log_print(ANDROID_LOG_INFO, __FUNCTION__, __VA_ARGS__); \
            } \
        } while (0)
#endif /* ADB_HOST */

#endif /* __ADB_TRACE_H */
