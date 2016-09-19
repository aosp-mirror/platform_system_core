/*
** Copyright 2006, The Android Open Source Project
**
** Licensed under the Apache License, Version 2.0 (the "License"); 
** you may not use this file except in compliance with the License. 
** You may obtain a copy of the License at 
**
**     http://www.apache.org/licenses/LICENSE-2.0 
**
** Unless required by applicable law or agreed to in writing, software 
** distributed under the License is distributed on an "AS IS" BASIS, 
** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
** See the License for the specific language governing permissions and 
** limitations under the License.
*/

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define LISTEN_BACKLOG 4

#if !defined(_WIN32)
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#endif

#include <cutils/sockets.h>

static int _socket_loopback_server(int family, int type, struct sockaddr * addr, size_t size)
{
    int s, n;

    s = socket(family, type, 0);
    if(s < 0)
        return -1;

    n = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (const char *) &n, sizeof(n));

    if(bind(s, addr, size) < 0) {
        close(s);
        return -1;
    }

    if (type == SOCK_STREAM) {
        int ret;

        ret = listen(s, LISTEN_BACKLOG);

        if (ret < 0) {
            close(s);
            return -1;
        }
    }

    return s;
}

/* open listen() port on loopback IPv6 interface */
int socket_loopback_server6(int port, int type)
{
    struct sockaddr_in6 addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_loopback;

    return _socket_loopback_server(AF_INET6, type, (struct sockaddr *) &addr, sizeof(addr));
}

/* open listen() port on loopback interface */
int socket_loopback_server(int port, int type)
{
    struct sockaddr_in addr;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    return _socket_loopback_server(AF_INET, type, (struct sockaddr *) &addr, sizeof(addr));
}
