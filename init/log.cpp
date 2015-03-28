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

#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>

#include <selinux/selinux.h>

#include "log.h"

static void init_klog_vwrite(int level, const char* fmt, va_list ap) {
    static const char* tag = basename(getprogname());

    char prefix[64];
    snprintf(prefix, sizeof(prefix), "<%d>%s: ", level, tag);

    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, ap);

    iovec iov[2];
    iov[0].iov_base = prefix;
    iov[0].iov_len = strlen(prefix);
    iov[1].iov_base = msg;
    iov[1].iov_len = strlen(msg);

    klog_writev(level, iov, 2);
}

void init_klog_write(int level, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    init_klog_vwrite(level, fmt, ap);
    va_end(ap);
}

int selinux_klog_callback(int type, const char *fmt, ...) {
    int level = KLOG_ERROR_LEVEL;
    if (type == SELINUX_WARNING) {
        level = KLOG_WARNING_LEVEL;
    } else if (type == SELINUX_INFO) {
        level = KLOG_INFO_LEVEL;
    }
    va_list ap;
    va_start(ap, fmt);
    init_klog_vwrite(level, fmt, ap);
    va_end(ap);
    return 0;
}
