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
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>

#include <cutils/sockets.h>

/* Connect to port on the IP interface. type is
 * SOCK_STREAM or SOCK_DGRAM. 
 * return is a file descriptor or -1 on error
 */
int socket_network_client(const char *host, int port, int type)
{
    return socket_network_client_timeout(host, port, type, 0);
}

/* Connect to port on the IP interface. type is SOCK_STREAM or SOCK_DGRAM.
 * timeout in seconds return is a file descriptor or -1 on error
 */
int socket_network_client_timeout(const char *host, int port, int type, int timeout)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int s;
    int flags = 0, error = 0, ret = 0;
    fd_set rset, wset;
    socklen_t len = sizeof(error);
    struct timeval ts;

    ts.tv_sec = timeout;
    ts.tv_usec = 0;

    hp = gethostbyname(host);
    if (hp == 0) return -1;

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = hp->h_addrtype;
    addr.sin_port = htons(port);
    memcpy(&addr.sin_addr, hp->h_addr, hp->h_length);

    s = socket(hp->h_addrtype, type, 0);
    if (s < 0) return -1;

    if ((flags = fcntl(s, F_GETFL, 0)) < 0) {
        close(s);
        return -1;
    }

    if (fcntl(s, F_SETFL, flags | O_NONBLOCK) < 0) {
        close(s);
        return -1;
    }

    if ((ret = connect(s, (struct sockaddr *) &addr, sizeof(addr))) < 0) {
        if (errno != EINPROGRESS) {
            close(s);
            return -1;
        }
    }

    if (ret == 0)
        goto done;

    FD_ZERO(&rset);
    FD_SET(s, &rset);
    wset = rset;

    if ((ret = select(s + 1, &rset, &wset, NULL, (timeout) ? &ts : NULL)) < 0) {
        close(s);
        return -1;
    }
    if (ret == 0) {   // we had a timeout
        errno = ETIMEDOUT;
        close(s);
        return -1;
    }

    if (FD_ISSET(s, &rset) || FD_ISSET(s, &wset)) {
        if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            close(s);
            return -1;
        }
    } else {
        close(s);
        return -1;
    }

    if (error) {  // check if we had a socket error
        errno = error;
        close(s);
        return -1;
    }

done:
    if (fcntl(s, F_SETFL, flags) < 0) {
        close(s);
        return -1;
    }

    return s;
}
