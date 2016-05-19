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

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

/* IMPORTANT: if you change the following list, don't
 * forget to update the corresponding 'tags' table in
 * the adb_trace_init() function implemented in adb_trace.cpp.
 */
enum AdbTrace {
    ADB = 0,   /* 0x001 */
    SOCKETS,
    PACKETS,
    TRANSPORT,
    RWX,       /* 0x010 */
    USB,
    SYNC,
    SYSDEPS,
    JDWP,      /* 0x100 */
    SERVICES,
    AUTH,
    FDEVENT,
    SHELL
};

#define VLOG_IS_ON(TAG) \
    ((adb_trace_mask & (1 << (TAG))) != 0)

#define VLOG(TAG)         \
    if (LIKELY(!VLOG_IS_ON(TAG))) \
        ;                 \
    else                  \
        LOG(INFO)

// You must define TRACE_TAG before using this macro.
#define D(...) \
    VLOG(TRACE_TAG) << android::base::StringPrintf(__VA_ARGS__)


extern int adb_trace_mask;
void adb_trace_init(char**);
void adb_trace_enable(AdbTrace trace_tag);

#endif /* __ADB_TRACE_H */
