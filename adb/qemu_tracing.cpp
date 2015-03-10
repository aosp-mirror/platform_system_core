/*
 * Copyright (C) 2015 The Android Open Source Project
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

/*
 * Implements ADB tracing inside the emulator.
 */

#include <stdarg.h>

#include "sysdeps.h"
#include "qemu_tracing.h"

/*
 * Redefine open and write for qemu_pipe.h that contains inlined references
 * to those routines. We will redifine them back after qemu_pipe.h inclusion.
 */

#undef open
#undef write
#define open    adb_open
#define write   adb_write
#include <hardware/qemu_pipe.h>
#undef open
#undef write
#define open    ___xxx_open
#define write   ___xxx_write

/* A handle to adb-debug qemud service in the emulator. */
int   adb_debug_qemu = -1;

/* Initializes connection with the adb-debug qemud service in the emulator. */
int adb_qemu_trace_init(void)
{
    char con_name[32];

    if (adb_debug_qemu >= 0) {
        return 0;
    }

    /* adb debugging QEMUD service connection request. */
    snprintf(con_name, sizeof(con_name), "qemud:adb-debug");
    adb_debug_qemu = qemu_pipe_open(con_name);
    return (adb_debug_qemu >= 0) ? 0 : -1;
}

void adb_qemu_trace(const char* fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    char msg[1024];

    if (adb_debug_qemu >= 0) {
        vsnprintf(msg, sizeof(msg), fmt, args);
        adb_write(adb_debug_qemu, msg, strlen(msg));
    }
}
