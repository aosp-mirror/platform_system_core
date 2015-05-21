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
} ;

#if !ADB_HOST
/*
 * When running inside the emulator, guest's adbd can connect to 'adb-debug'
 * qemud service that can display adb trace messages (on condition that emulator
 * has been started with '-debug adb' option).
 */

/* Delivers a trace message to the emulator via QEMU pipe. */
void adb_qemu_trace(const char* fmt, ...);
/* Macro to use to send ADB trace messages to the emulator. */
#define DQ(...)    adb_qemu_trace(__VA_ARGS__)
#else
#define DQ(...) ((void)0)
#endif  /* !ADB_HOST */

extern int adb_trace_mask;
extern unsigned char adb_trace_output_count;
void adb_trace_init(char**);

#  define ADB_TRACING  ((adb_trace_mask & (1 << TRACE_TAG)) != 0)

/* you must define TRACE_TAG before using this macro */
#if ADB_HOST
#  define  D(...)                                      \
        do {                                           \
            if (ADB_TRACING) {                         \
                int save_errno = errno;                \
                adb_mutex_lock(&D_lock);               \
                fprintf(stderr, "%16s: %5d:%5lu | ",   \
                        __FUNCTION__,                  \
                        getpid(), adb_thread_id());    \
                errno = save_errno;                    \
                fprintf(stderr, __VA_ARGS__ );         \
                fflush(stderr);                        \
                adb_mutex_unlock(&D_lock);             \
                errno = save_errno;                    \
           }                                           \
        } while (0)
#  define  DR(...)                                     \
        do {                                           \
            if (ADB_TRACING) {                         \
                int save_errno = errno;                \
                adb_mutex_lock(&D_lock);               \
                errno = save_errno;                    \
                fprintf(stderr, __VA_ARGS__ );         \
                fflush(stderr);                        \
                adb_mutex_unlock(&D_lock);             \
                errno = save_errno;                    \
           }                                           \
        } while (0)
#else
#  define  D(...)                                      \
        do {                                           \
            if (ADB_TRACING) {                         \
                __android_log_print(                   \
                    ANDROID_LOG_INFO,                  \
                    __FUNCTION__,                      \
                    __VA_ARGS__ );                     \
            }                                          \
        } while (0)
#  define  DR(...)                                     \
        do {                                           \
            if (ADB_TRACING) {                         \
                __android_log_print(                   \
                    ANDROID_LOG_INFO,                  \
                    __FUNCTION__,                      \
                    __VA_ARGS__ );                     \
            }                                          \
        } while (0)
#endif /* ADB_HOST */

#endif /* __ADB_TRACE_H */
