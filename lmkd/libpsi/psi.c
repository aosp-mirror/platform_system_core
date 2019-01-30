/*
 * Copyright (C) 2018 The Android Open Source Project
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

#define LOG_TAG "libpsi"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>

#include <log/log.h>
#include "psi/psi.h"

#define PSI_MON_FILE_MEMORY "/proc/pressure/memory"

static const char* stall_type_name[] = {
        "some",
        "full",
};

int init_psi_monitor(enum psi_stall_type stall_type,
             int threshold_us, int window_us) {
    int fd;
    int res;
    char buf[256];

    fd = TEMP_FAILURE_RETRY(open(PSI_MON_FILE_MEMORY, O_WRONLY | O_CLOEXEC));
    if (fd < 0) {
        ALOGE("No kernel psi monitor support (errno=%d)", errno);
        return -1;
    }

    switch (stall_type) {
    case (PSI_SOME):
    case (PSI_FULL):
        res = snprintf(buf, sizeof(buf), "%s %d %d",
            stall_type_name[stall_type], threshold_us, window_us);
        break;
    default:
        ALOGE("Invalid psi stall type: %d", stall_type);
        errno = EINVAL;
        goto err;
    }

    if (res >= (ssize_t)sizeof(buf)) {
        ALOGE("%s line overflow for psi stall type '%s'",
            PSI_MON_FILE_MEMORY, stall_type_name[stall_type]);
        errno = EINVAL;
        goto err;
    }

    res = TEMP_FAILURE_RETRY(write(fd, buf, strlen(buf) + 1));
    if (res < 0) {
        ALOGE("%s write failed for psi stall type '%s'; errno=%d",
            PSI_MON_FILE_MEMORY, stall_type_name[stall_type], errno);
        goto err;
    }

    return fd;

err:
    close(fd);
    return -1;
}

int register_psi_monitor(int epollfd, int fd, void* data) {
    int res;
    struct epoll_event epev;

    epev.events = EPOLLPRI;
    epev.data.ptr = data;
    res = epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &epev);
    if (res < 0) {
        ALOGE("epoll_ctl for psi monitor failed; errno=%d", errno);
    }
    return res;
}

int unregister_psi_monitor(int epollfd, int fd) {
    return epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, NULL);
}

void destroy_psi_monitor(int fd) {
    if (fd >= 0) {
        close(fd);
    }
}
