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

#include <base/logging.h>
#include <base/stringprintf.h>

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

#define ADB_TRACING  ((adb_trace_mask & (1 << TRACE_TAG)) != 0)

// You must define TRACE_TAG before using this macro.
#define D(...) \
        do { \
            if (ADB_TRACING) { \
                int saved_errno = errno; \
                LOG(INFO) << android::base::StringPrintf(__VA_ARGS__); \
                errno = saved_errno; \
           } \
        } while (0)

#endif /* __ADB_TRACE_H */
