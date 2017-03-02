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


// Define QEMU_PIPE_DEBUG if you want to print error messages when an error
// occurs during pipe operations. The macro should simply take a printf-style
// formatting string followed by optional arguments.
#ifndef QEMU_PIPE_DEBUG
#  define  QEMU_PIPE_DEBUG(...)   (void)0
#endif

// Try to open a new Qemu fast-pipe. This function returns a file descriptor
// that can be used to communicate with a named service managed by the
// emulator.
//
// This file descriptor can be used as a standard pipe/socket descriptor.
//
// 'pipeName' is the name of the emulator service you want to connect to,
// and must begin with 'pipe:' (e.g. 'pipe:camera' or 'pipe:opengles').
//
// On success, return a valid file descriptor, or -1/errno on failure. E.g.:
//
// EINVAL  -> unknown/unsupported pipeName
// ENOSYS  -> fast pipes not available in this system.
//
// ENOSYS should never happen, except if you're trying to run within a
// misconfigured emulator.
//
// You should be able to open several pipes to the same pipe service,
// except for a few special cases (e.g. GSM modem), where EBUSY will be
// returned if more than one client tries to connect to it.
int qemu_pipe_open(const char* pipeName) {
    // Sanity check.
    if (!pipeName || memcmp(pipeName, "pipe:", 5) != 0) {
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
    ssize_t ret = TEMP_FAILURE_RETRY(write(fd, pipeName, pipeNameLen + 1U));
    if (ret != (ssize_t)pipeNameLen + 1) {
        QEMU_PIPE_DEBUG("%s: Could not connect to %s pipe service: %s",
                        __FUNCTION__, pipeName, strerror(errno));
        if (ret == 0) {
            errno = ECONNRESET;
        } else if (ret > 0) {
            errno = EINVAL;
        }
        return -1;
    }
    return fd;
}

// Send a framed message |buff| of |len| bytes through the |fd| descriptor.
// This really adds a 4-hexchar prefix describing the payload size.
// Returns 0 on success, and -1 on error.
int qemu_pipe_frame_send(int fd, const void* buff, size_t len) {
    char header[5];
    snprintf(header, sizeof(header), "%04zx", len);
    ssize_t ret = TEMP_FAILURE_RETRY(write(fd, header, 4));
    if (ret != 4) {
        QEMU_PIPE_DEBUG("Can't write qemud frame header: %s", strerror(errno));
        return -1;
    }
    ret = TEMP_FAILURE_RETRY(write(fd, buff, len));
    if (ret != (ssize_t)len) {
        QEMU_PIPE_DEBUG("Can't write qemud frame payload: %s", strerror(errno));
        return -1;
    }
    return 0;
}

// Read a frame message from |fd|, and store it into |buff| of |len| bytes.
// If the framed message is larger than |len|, then this returns -1 and the
// content is lost. Otherwise, this returns the size of the message. NOTE:
// empty messages are possible in a framed wire protocol and do not mean
// end-of-stream.
int qemu_pipe_frame_recv(int fd, void* buff, size_t len) {
    char header[5];
    ssize_t ret = TEMP_FAILURE_RETRY(read(fd, header, 4));
    if (ret != 4) {
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
    ret = TEMP_FAILURE_RETRY(read(fd, buff, size));
    if (ret != (ssize_t)size) {
        QEMU_PIPE_DEBUG("Could not read qemud frame payload: %s",
                        strerror(errno));
        return -1;
    }
    return size;
}
