/*
 * Copyright (c) 2009-2013, Google Inc.
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
 *  * Neither the name of Google, Inc. nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
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

#include <stdio.h>
#include <cutils/sockets.h>
#include <poll.h>
#include <unistd.h>

#include "utils.h"

#define BUFFER_SIZE 256

#define STDIN_FD 0
#define STDOUT_FD 1
#define STDERR_FD 2

void run_socket_client() {
    int fd;
    char buffer[BUFFER_SIZE];
    int n;
    struct pollfd fds[2];

    fd = socket_local_client("fastbootd",
                         ANDROID_SOCKET_NAMESPACE_RESERVED,
                         SOCK_STREAM);

    if (fd < 0) {
        fprintf(stderr, "ERROR: Unable to open fastbootd socket\n");
        return;
    }

    fds[0].fd = STDIN_FD;
    fds[0].events = POLLIN;
    fds[1].fd = fd;
    fds[1].events = POLLIN;

    while(true) {
        if (poll(fds, 2, -1) <= 0) {
            fprintf(stderr, "ERROR: socket error");
            return;
        }

        if (fds[0].revents & POLLIN) {
            if ((n = read(STDIN_FD, buffer, BUFFER_SIZE)) < 0) {
                goto error;
            }

            if (bulk_write(fd, buffer, n) < 0) {
                goto error;
            }
        }

        if (fds[1].revents & POLLIN) {
            if ((n = read(fd, buffer, BUFFER_SIZE)) < 0) {
                goto error;
            }

            if (bulk_write(STDOUT_FD, buffer, n) < 0) {
                goto error;
            }
        }
    }

error:
    fprintf(stderr, "Transport error\n");
}
