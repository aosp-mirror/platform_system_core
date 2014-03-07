/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cutils/klog.h>

static int klog_fd = -1;
static int klog_level = KLOG_DEFAULT_LEVEL;

int klog_get_level(void) {
    return klog_level;
}

void klog_set_level(int level) {
    klog_level = level;
}

void klog_init(void)
{
    static const char *name = "/dev/__kmsg__";

    if (klog_fd >= 0) return; /* Already initialized */

    if (mknod(name, S_IFCHR | 0600, (1 << 8) | 11) == 0) {
        klog_fd = open(name, O_WRONLY);
        if (klog_fd < 0)
                return;
        fcntl(klog_fd, F_SETFD, FD_CLOEXEC);
        unlink(name);
    }
}

#define LOG_BUF_MAX 512

void klog_vwrite(int level, const char *fmt, va_list ap)
{
    char buf[LOG_BUF_MAX];

    if (level > klog_level) return;
    if (klog_fd < 0) klog_init();
    if (klog_fd < 0) return;

    vsnprintf(buf, LOG_BUF_MAX, fmt, ap);
    buf[LOG_BUF_MAX - 1] = 0;

    write(klog_fd, buf, strlen(buf));
}

void klog_write(int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    klog_vwrite(level, fmt, ap);
    va_end(ap);
}
