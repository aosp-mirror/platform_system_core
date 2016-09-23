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

#include <cutils/sockets.h>

#if !defined(_WIN32)
#include <netinet/in.h>
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
    char key[64];
    snprintf(key, sizeof(key), ANDROID_SOCKET_ENV_PREFIX "%s", name);

    const char* val = getenv(key);
    if (!val) {
        return -1;
    }

    errno = 0;
    long ret = strtol(val, NULL, 10);
    if (errno) {
        return -1;
    }
    if (ret < 0 || ret > INT_MAX) {
        return -1;
    }

    return static_cast<int>(ret);
}
