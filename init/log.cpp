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

#include "log.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <selinux/selinux.h>

static const int kLogSeverityToKLogLevel[] = {
    KLOG_NOTICE_LEVEL, KLOG_DEBUG_LEVEL, KLOG_INFO_LEVEL,
    KLOG_WARNING_LEVEL, KLOG_ERROR_LEVEL, KLOG_ERROR_LEVEL,
};
static_assert(arraysize(kLogSeverityToKLogLevel) == android::base::FATAL + 1,
              "Mismatch in size of kLogSeverityToKLogLevel and values in LogSeverity");

static void KernelLogger(android::base::LogId, android::base::LogSeverity severity,
                         const char* tag, const char*, unsigned int, const char* msg) {
    int level = kLogSeverityToKLogLevel[severity];
    if (level > klog_get_level()) return;

    // The kernel's printk buffer is only 1024 bytes.
    // TODO: should we automatically break up long lines into multiple lines?
    // Or we could log but with something like "..." at the end?
    char buf[1024];
    size_t size = snprintf(buf, sizeof(buf), "<%d>%s: %s\n", level, tag, msg);
    if (size > sizeof(buf)) {
        size = snprintf(buf, sizeof(buf), "<%d>%s: %zu-byte message too long for printk\n",
                        level, tag, size);
    }

    iovec iov[1];
    iov[0].iov_base = buf;
    iov[0].iov_len = size;
    klog_writev(level, iov, 1);
}

void InitKernelLogging(char* argv[]) {
    // Make stdin/stdout/stderr all point to /dev/null.
    int fd = open("/sys/fs/selinux/null", O_RDWR);
    if (fd == -1) {
        int saved_errno = errno;
        android::base::InitLogging(argv, &KernelLogger);
        errno = saved_errno;
        PLOG(FATAL) << "Couldn't open /sys/fs/selinux/null";
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    if (fd > 2) close(fd);

    android::base::InitLogging(argv, &KernelLogger);
    klog_set_level(KLOG_NOTICE_LEVEL);
}

int selinux_klog_callback(int type, const char *fmt, ...) {
    android::base::LogSeverity severity = android::base::ERROR;
    if (type == SELINUX_WARNING) {
        severity = android::base::WARNING;
    } else if (type == SELINUX_INFO) {
        severity = android::base::INFO;
    }
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    KernelLogger(android::base::MAIN, severity, "selinux", nullptr, 0, buf);
    return 0;
}
