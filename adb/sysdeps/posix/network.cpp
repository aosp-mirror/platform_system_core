/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "sysdeps/network.h"

#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <string>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <cutils/sockets.h>

#include "adb_unique_fd.h"

static void set_error(std::string* error) {
    if (error) {
        *error = strerror(errno);
    }
}

static sockaddr* loopback_addr4(sockaddr_storage* addr, socklen_t* addrlen, int port) {
    struct sockaddr_in* addr4 = reinterpret_cast<sockaddr_in*>(addr);
    *addrlen = sizeof(*addr4);

    addr4->sin_family = AF_INET;
    addr4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr4->sin_port = htons(port);
    return reinterpret_cast<sockaddr*>(addr);
}

static sockaddr* loopback_addr6(sockaddr_storage* addr, socklen_t* addrlen, int port) {
    struct sockaddr_in6* addr6 = reinterpret_cast<sockaddr_in6*>(addr);
    *addrlen = sizeof(*addr6);

    addr6->sin6_family = AF_INET6;
    addr6->sin6_addr = in6addr_loopback;
    addr6->sin6_port = htons(port);
    return reinterpret_cast<sockaddr*>(addr);
}

static int _network_loopback_client(bool ipv6, int port, int type, std::string* error) {
    unique_fd s(socket(ipv6 ? AF_INET6 : AF_INET, type, 0));
    if (s == -1) {
        set_error(error);
        return -1;
    }

    struct sockaddr_storage addr_storage = {};
    socklen_t addrlen = sizeof(addr_storage);
    sockaddr* addr = (ipv6 ? loopback_addr6 : loopback_addr4)(&addr_storage, &addrlen, 0);

    if (bind(s.get(), addr, addrlen) != 0) {
        set_error(error);
        return -1;
    }

    addr = (ipv6 ? loopback_addr6 : loopback_addr4)(&addr_storage, &addrlen, port);

    if (connect(s.get(), addr, addrlen) != 0) {
        set_error(error);
        return -1;
    }

    return s.release();
}

int network_loopback_client(int port, int type, std::string* error) {
    // Try IPv4 first, use IPv6 as a fallback.
    int rc = _network_loopback_client(false, port, type, error);
    if (rc == -1) {
        return _network_loopback_client(true, port, type, error);
    }
    return rc;
}

static int _network_loopback_server(bool ipv6, int port, int type, std::string* error) {
    unique_fd s(socket(ipv6 ? AF_INET6 : AF_INET, type, 0));
    if (s == -1) {
        set_error(error);
        return -1;
    }

    int n = 1;
    setsockopt(s.get(), SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));

    struct sockaddr_storage addr_storage = {};
    socklen_t addrlen = sizeof(addr_storage);
    sockaddr* addr = (ipv6 ? loopback_addr6 : loopback_addr4)(&addr_storage, &addrlen, port);

    if (bind(s.get(), addr, addrlen) != 0) {
        set_error(error);
        return -1;
    }

    if (type == SOCK_STREAM || type == SOCK_SEQPACKET) {
        if (listen(s.get(), SOMAXCONN) != 0) {
            set_error(error);
            return -1;
        }
    }

    return s.release();
}

int network_loopback_server(int port, int type, std::string* error, bool prefer_ipv4) {
    int rc = -1;
    if (prefer_ipv4) {
        rc = _network_loopback_server(false, port, type, error);
    }

    // Only attempt to listen on IPv6 if IPv4 is unavailable or prefer_ipv4 is false
    // We don't want to start an IPv6 server if there's already an IPv4 one running.
    if (rc == -1 && (errno == EADDRNOTAVAIL || errno == EAFNOSUPPORT || !prefer_ipv4)) {
        return _network_loopback_server(true, port, type, error);
    }
    return rc;
}

int network_connect(const std::string& host, int port, int type, int timeout, std::string* error) {
    int getaddrinfo_error = 0;
    int fd = socket_network_client_timeout(host.c_str(), port, type, timeout, &getaddrinfo_error);
    if (fd != -1) {
        return fd;
    }
    if (getaddrinfo_error != 0) {
        *error = android::base::StringPrintf("failed to resolve host: '%s': %s", host.c_str(),
                                             gai_strerror(getaddrinfo_error));
        LOG(WARNING) << *error;
    } else {
        *error = android::base::StringPrintf("failed to connect to '%s:%d': %s", host.c_str(), port,
                                             strerror(errno));
        LOG(WARNING) << *error;
    }
    return -1;
}
