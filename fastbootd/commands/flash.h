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

#ifndef _FASTBOOTD_ERASE_H
#define _FASTBOOTD_ERASE_H

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include "debug.h"

int flash_find_entry(const char *, char *, size_t);
int flash_erase(int fd);

static inline int flash_get_partiton(const char *path) {
    return open(path, O_RDWR);
}

static inline int flash_close(int fd) {
    return close(fd);
}

int flash_write(int partition, int data, ssize_t size, ssize_t skip);

static inline ssize_t read_data_once(int fd, char *buffer, ssize_t size) {
    ssize_t readcount = 0;
    ssize_t len;

    while ((len = TEMP_FAILURE_RETRY(read(fd, (void *) &buffer[readcount], size - readcount))) > 0) {
        readcount += len;
    }
    if (len < 0) {
        D(ERR, "Read error:%s", strerror(errno));
        return len;
    }

    return readcount;
}

int flash_validate_certificate(int signed_fd, int *data_fd);

#endif

