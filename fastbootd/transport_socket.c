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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cutils/sockets.h>

#include "debug.h"
#include "transport.h"
#include "utils.h"


#define container_of(ptr, type, member) \
    ((type*)((char*)(ptr) - offsetof(type, member)))

#define SOCKET_WORKING 0
#define SOCKET_STOPPED -1


struct socket_transport {
    struct transport transport;

    int fd;
};

struct socket_handle {
    struct transport_handle handle;

    int fd;
};

void socket_close(struct transport_handle *thandle)
{
    struct socket_handle * handle = container_of(thandle, struct socket_handle, handle);
    close(handle->fd);
}

struct transport_handle *socket_connect(struct transport *transport)
{
    struct socket_handle *handle = calloc(sizeof(struct socket_handle), 1);
    struct socket_transport *socket_transport = container_of(transport, struct socket_transport, transport);
    struct sockaddr addr;
    socklen_t alen = sizeof(addr);

    handle->fd = accept(socket_transport->fd, &addr, &alen);

    if (handle->fd < 0) {
        D(WARN, "socket connect error");
        return NULL;
    }

    D(DEBUG, "[ socket_thread - registering device ]");
    return &handle->handle;
}

ssize_t socket_write(struct transport_handle *thandle, const void *data, size_t len)
{
    ssize_t ret;
    struct socket_handle *handle = container_of(thandle, struct socket_handle, handle);

    D(DEBUG, "about to write (fd=%d, len=%zu)", handle->fd, len);
    ret = bulk_write(handle->fd, data, len);
    if (ret < 0) {
        D(ERR, "ERROR: fd = %d, ret = %zd", handle->fd, ret);
        return -1;
    }
    D(DEBUG, "[ socket_write done fd=%d ]", handle->fd);
    return ret;
}

ssize_t socket_read(struct transport_handle *thandle, void *data, size_t len)
{
    ssize_t ret;
    struct socket_handle *handle = container_of(thandle, struct socket_handle, handle);

    D(DEBUG, "about to read (fd=%d, len=%zu)", handle->fd, len);
    ret = bulk_read(handle->fd, data, len);
    if (ret < 0) {
        D(ERR, "ERROR: fd = %d, ret = %zd", handle->fd, ret);
        return -1;
    }
    D(DEBUG, "[ socket_read done fd=%d ret=%zd]", handle->fd, ret);
    return ret;
}

static int listen_socket_init(struct socket_transport *socket_transport)
{
    int s = android_get_control_socket("fastbootd");

    if (s < 0) {
        D(WARN, "android_get_control_socket(fastbootd): %s\n", strerror(errno));
        return 0;
    }

    if (listen(s, 4) < 0) {
        D(WARN, "listen(control socket): %s\n", strerror(errno));
        return 0;
    }

    socket_transport->fd = s;

    return 1;
}


int transport_socket_init()
{
    struct socket_transport *socket_transport = malloc(sizeof(struct socket_transport));

    socket_transport->transport.connect = socket_connect;
    socket_transport->transport.close = socket_close;
    socket_transport->transport.read = socket_read;
    socket_transport->transport.write = socket_write;

    if (!listen_socket_init(socket_transport)) {
        D(ERR, "socket transport init failed");
        free(socket_transport);
        return 0;
    }

    transport_register(&socket_transport->transport);
    return 1;
}

