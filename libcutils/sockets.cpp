/*
 * Copyright (C) 2016 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

// This file contains socket implementation that can be shared between
// platforms as long as the correct headers are included.
#define _GNU_SOURCE 1 // For asprintf

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#if !defined(_WIN32)
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#if !defined(_WIN32)
#include <sys/un.h>
#endif
#include <unistd.h>

#include <string>

#include <cutils/sockets.h>

#ifndef TEMP_FAILURE_RETRY // _WIN32 does not define
#define TEMP_FAILURE_RETRY(exp) (exp)
#endif

int socket_get_local_port(cutils_socket_t sock) {
    sockaddr_storage addr;
    socklen_t addr_size = sizeof(addr);

    if (getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &addr_size) == 0) {
        // sockaddr_in and sockaddr_in6 always overlap the port field.
        return ntohs(reinterpret_cast<sockaddr_in*>(&addr)->sin_port);
    }
    return -1;
}

int android_get_control_socket(const char* name) {
    char *key = NULL;
    if (asprintf(&key, ANDROID_SOCKET_ENV_PREFIX "%s", name) < 0) return -1;
    if (!key) return -1;

    char *cp = key;
    while (*cp) {
        if (!isalnum(*cp)) *cp = '_';
        ++cp;
    }

    const char* val = getenv(key);
    free(key);
    if (!val) return -1;

    errno = 0;
    long fd = strtol(val, NULL, 10);
    if (errno) return -1;

    // validity checking
    if ((fd < 0) || (fd > INT_MAX)) return -1;
#if defined(_SC_OPEN_MAX)
    if (fd >= sysconf(_SC_OPEN_MAX)) return -1;
#elif defined(OPEN_MAX)
    if (fd >= OPEN_MAX) return -1;
#elif defined(_POSIX_OPEN_MAX)
    if (fd >= _POSIX_OPEN_MAX) return -1;
#endif

#if defined(F_GETFD)
    if (TEMP_FAILURE_RETRY(fcntl(fd, F_GETFD)) < 0) return -1;
#elif defined(F_GETFL)
    if (TEMP_FAILURE_RETRY(fcntl(fd, F_GETFL)) < 0) return -1;
#else
    struct stat s;
    if (TEMP_FAILURE_RETRY(fstat(fd, &s)) < 0) return -1;
#endif

#if !defined(_WIN32)
    struct sockaddr_un addr;
    socklen_t addrlen = sizeof(addr);
    int ret = TEMP_FAILURE_RETRY(getsockname(fd, (struct sockaddr *)&addr, &addrlen));
    if (ret < 0) return -1;
    char *path = NULL;
    if (asprintf(&path, ANDROID_SOCKET_DIR"/%s", name) < 0) return -1;
    if (!path) return -1;
    int cmp = strcmp(addr.sun_path, path);
    free(path);
    if (cmp != 0) return -1;
#endif

    // It is what we think it is
    return static_cast<int>(fd);
}
