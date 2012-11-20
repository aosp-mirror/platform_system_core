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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <cutils/atomic.h>
#include <cutils/compiler.h>
#include <cutils/properties.h>
#include <cutils/trace.h>

#define LOG_TAG "cutils-trace"
#include <cutils/log.h>

int32_t               atrace_is_ready     = 0;
int                   atrace_marker_fd    = -1;
uint64_t              atrace_enabled_tags = ATRACE_TAG_NOT_READY;
static pthread_once_t atrace_once_control = PTHREAD_ONCE_INIT;
static pthread_mutex_t atrace_tags_mutex = PTHREAD_MUTEX_INITIALIZER;

// Read the sysprop and return the value tags should be set to
static uint64_t atrace_get_property()
{
    char value[PROPERTY_VALUE_MAX];
    char *endptr;
    uint64_t tags;

    property_get("debug.atrace.tags.enableflags", value, "0");
    errno = 0;
    tags = strtoull(value, &endptr, 0);
    if (value[0] == '\0' || *endptr != '\0') {
        ALOGE("Error parsing trace property: Not a number: %s", value);
        return 0;
    } else if (errno == ERANGE || tags == ULLONG_MAX) {
        ALOGE("Error parsing trace property: Number too large: %s", value);
        return 0;
    }
    return (tags | ATRACE_TAG_ALWAYS) & ATRACE_TAG_VALID_MASK;
}

// Update tags if tracing is ready. Useful as a sysprop change callback.
void atrace_update_tags()
{
    uint64_t tags;
    if (CC_UNLIKELY(android_atomic_acquire_load(&atrace_is_ready))) {
        tags = atrace_get_property();
        pthread_mutex_lock(&atrace_tags_mutex);
        atrace_enabled_tags = tags;
        pthread_mutex_unlock(&atrace_tags_mutex);
    }
}

static void atrace_init_once()
{
    atrace_marker_fd = open("/sys/kernel/debug/tracing/trace_marker", O_WRONLY);
    if (atrace_marker_fd == -1) {
        ALOGE("Error opening trace file: %s (%d)", strerror(errno), errno);
        atrace_enabled_tags = 0;
        goto done;
    }

    atrace_enabled_tags = atrace_get_property();

done:
    android_atomic_release_store(1, &atrace_is_ready);
}

void atrace_setup()
{
    pthread_once(&atrace_once_control, atrace_init_once);
}
