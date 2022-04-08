/*
 * Copyright (C) 2011 The Android Open Source Project
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

#include "qemu_pipe.h"

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>

#include <android-base/file.h>

using android::base::ReadFully;
using android::base::WriteFully;

// Define QEMU_PIPE_DEBUG if you want to print error messages when an error
// occurs during pipe operations. The macro should simply take a printf-style
// formatting string followed by optional arguments.
#ifndef QEMU_PIPE_DEBUG
#  define  QEMU_PIPE_DEBUG(...)   (void)0
#endif

int qemu_pipe_open(const char* pipeName) {
    // Sanity check.
    if (!pipeName) {
        errno = EINVAL;
        return -1;
    }

    int fd = TEMP_FAILURE_RETRY(open("/dev/qemu_pipe", O_RDWR));
    if (fd < 0) {
        QEMU_PIPE_DEBUG("%s: Could not open /dev/qemu_pipe: %s", __FUNCTION__,
                        strerror(errno));
        return -1;
    }

    // Write the pipe name, *including* the trailing zero which is necessary.
    size_t pipeNameLen = strlen(pipeName);
    if (WriteFully(fd, pipeName, pipeNameLen + 1U)) {
        return fd;
    }

    // now, add 'pipe:' prefix and try again
    // Note: host side will wait for the trailing '\0' to start
    // service lookup.
    const char pipe_prefix[] = "pipe:";
    if (WriteFully(fd, pipe_prefix, strlen(pipe_prefix)) &&
            WriteFully(fd, pipeName, pipeNameLen + 1U)) {
        return fd;
    }
    QEMU_PIPE_DEBUG("%s: Could not write to %s pipe service: %s",
            __FUNCTION__, pipeName, strerror(errno));
    close(fd);
    return -1;
}

int qemu_pipe_frame_send(int fd, const void* buff, size_t len) {
    char header[5];
    snprintf(header, sizeof(header), "%04zx", len);
    if (!WriteFully(fd, header, 4)) {
        QEMU_PIPE_DEBUG("Can't write qemud frame header: %s", strerror(errno));
        return -1;
    }
    if (!WriteFully(fd, buff, len)) {
        QEMU_PIPE_DEBUG("Can't write qemud frame payload: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int qemu_pipe_frame_recv(int fd, void* buff, size_t len) {
    char header[5];
    if (!ReadFully(fd, header, 4)) {
        QEMU_PIPE_DEBUG("Can't read qemud frame header: %s", strerror(errno));
        return -1;
    }
    header[4] = '\0';
    size_t size;
    if (sscanf(header, "%04zx", &size) != 1) {
        QEMU_PIPE_DEBUG("Malformed qemud frame header: [%.*s]", 4, header);
        return -1;
    }
    if (size > len) {
        QEMU_PIPE_DEBUG("Oversized qemud frame (% bytes, expected <= %)", size,
                        len);
        return -1;
    }
    if (!ReadFully(fd, buff, size)) {
        QEMU_PIPE_DEBUG("Could not read qemud frame payload: %s",
                        strerror(errno));
        return -1;
    }
    return size;
}
