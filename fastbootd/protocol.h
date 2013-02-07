/*
 * Copyright (c) 2013, Google Inc.
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

#ifndef _FASTBOOTD_PROTOCOL_H_
#define _FASTBOOTD_PROTOCOL_H_

#include <pthread.h>
#include <stddef.h>

struct protocol_handle {
    struct transport_handle *transport_handle;
    unsigned int state;
    int download_fd;

    pthread_mutex_t lock;
};

void fastboot_register(const char *prefix,
               void (*handle)(struct protocol_handle *handle, const char *arg));

void fastboot_publish(const char *name, const char *value);
const char *fastboot_getvar(const char *name);

struct protocol_handle *create_protocol_handle(struct transport_handle *t);
void protocol_handle_command(struct protocol_handle *handle, char *buffer);
int protocol_handle_download(struct protocol_handle *phandle, size_t len);
int protocol_get_download(struct protocol_handle *phandle);

void fastboot_fail(struct protocol_handle *handle, const char *reason);
void fastboot_okay(struct protocol_handle *handle, const char *reason);
void fastboot_data(struct protocol_handle *handle, size_t len);

#endif
