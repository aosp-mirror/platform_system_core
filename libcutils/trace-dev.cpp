/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <cutils/trace.h>

#include "trace-dev.inc"

static pthread_once_t atrace_once_control = PTHREAD_ONCE_INIT;

// Set whether tracing is enabled in this process.  This is used to prevent
// the Zygote process from tracing.
void atrace_set_tracing_enabled(bool enabled)
{
    atomic_store_explicit(&atrace_is_enabled, enabled, memory_order_release);
    atomic_store_explicit(&atrace_is_ready, false, memory_order_release);
    atrace_update_tags();
}

static void atrace_init_once()
{
    atrace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY | O_CLOEXEC);
    if (atrace_marker_fd == -1) {
        ALOGE("Error opening trace file: %s (%d)", strerror(errno), errno);
        atrace_enabled_tags = 0;
        return;
    }
    atrace_enabled_tags = atrace_get_property();
}

void atrace_setup()
{
    if (atomic_load_explicit(&atrace_is_enabled, memory_order_acquire)) {
        pthread_once(&atrace_once_control, atrace_init_once);
    }
    atomic_store_explicit(&atrace_is_ready, true, memory_order_release);
}

void atrace_begin_body(const char* name)
{
    WRITE_MSG("B|%d|", "%s", name, "");
}

void atrace_end_body()
{
    WRITE_MSG("E|%d", "%s", "", "");
}

void atrace_async_begin_body(const char* name, int32_t cookie)
{
    WRITE_MSG("S|%d|", "|%" PRId32, name, cookie);
}

void atrace_async_end_body(const char* name, int32_t cookie)
{
    WRITE_MSG("F|%d|", "|%" PRId32, name, cookie);
}

void atrace_int_body(const char* name, int32_t value)
{
    WRITE_MSG("C|%d|", "|%" PRId32, name, value);
}

void atrace_int64_body(const char* name, int64_t value)
{
    WRITE_MSG("C|%d|", "|%" PRId64, name, value);
}
