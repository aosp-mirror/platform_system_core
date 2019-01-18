/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "socket_spec.h"

#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <android-base/parseint.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "sysdeps.h"

using namespace std::string_literals;

using android::base::StringPrintf;

#if defined(__linux__)
#define ADB_LINUX 1
#else
#define ADB_LINUX 0
#endif

#if defined(_WIN32)
#define ADB_WINDOWS 1
#else
#define ADB_WINDOWS 0
#endif

// Not static because it is used in commandline.c.
int gListenAll = 0;

struct LocalSocketType {
    int socket_namespace;
    bool available;
};

static auto& kLocalSocketTypes = *new std::unordered_map<std::string, LocalSocketType>({
#if ADB_HOST
    { "local", { ANDROID_SOCKET_NAMESPACE_FILESYSTEM, !ADB_WINDOWS } },
#else
    { "local", { ANDROID_SOCKET_NAMESPACE_RESERVED, !ADB_WINDOWS } },
#endif

    { "localreserved", { ANDROID_SOCKET_NAMESPACE_RESERVED, !ADB_HOST } },
    { "localabstract", { ANDROID_SOCKET_NAMESPACE_ABSTRACT, ADB_LINUX } },
    { "localfilesystem", { ANDROID_SOCKET_NAMESPACE_FILESYSTEM, !ADB_WINDOWS } },
});

bool parse_tcp_socket_spec(std::string_view spec, std::string* hostname, int* port,
                           std::string* serial, std::string* error) {
    if (!spec.starts_with("tcp:")) {
        *error = "specification is not tcp: ";
        *error += spec;
        return false;
    }

    std::string hostname_value;
    int port_value;

    // If the spec is tcp:<port>, parse it ourselves.
    // Otherwise, delegate to android::base::ParseNetAddress.
    if (android::base::ParseInt(&spec[4], &port_value)) {
        // Do the range checking ourselves, because ParseInt rejects 'tcp:65536' and 'tcp:foo:1234'
        // identically.
        if (port_value < 0 || port_value > 65535) {
            *error = StringPrintf("bad port number '%d'", port_value);
            return false;
        }
    } else {
        std::string addr(spec.substr(4));
        port_value = -1;

        // FIXME: ParseNetAddress rejects port 0. This currently doesn't hurt, because listening
        //        on an address that isn't 'localhost' is unsupported.
        if (!android::base::ParseNetAddress(addr, &hostname_value, &port_value, serial, error)) {
            return false;
        }

        if (port_value == -1) {
            *error = "missing port in specification: ";
            *error += spec;
            return false;
        }
    }

    if (hostname) {
        *hostname = std::move(hostname_value);
    }

    if (port) {
        *port = port_value;
    }

    return true;
}

static bool tcp_host_is_local(std::string_view hostname) {
    // FIXME
    return hostname.empty() || hostname == "localhost";
}

bool is_socket_spec(std::string_view spec) {
    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (spec.starts_with(prefix)) {
            return true;
        }
    }
    return spec.starts_with("tcp:");
}

bool is_local_socket_spec(std::string_view spec) {
    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (spec.starts_with(prefix)) {
            return true;
        }
    }

    std::string error;
    std::string hostname;
    if (!parse_tcp_socket_spec(spec, &hostname, nullptr, nullptr, &error)) {
        return false;
    }
    return tcp_host_is_local(hostname);
}

bool socket_spec_connect(unique_fd* fd, std::string_view address, int* port, std::string* serial,
                         std::string* error) {
    if (address.starts_with("tcp:")) {
        std::string hostname;
        int port_value = port ? *port : 0;
        if (!parse_tcp_socket_spec(address, &hostname, &port_value, serial, error)) {
            return false;
        }

        if (tcp_host_is_local(hostname)) {
            fd->reset(network_loopback_client(port_value, SOCK_STREAM, error));
        } else {
#if ADB_HOST
            fd->reset(network_connect(hostname, port_value, SOCK_STREAM, 0, error));
#else
            // Disallow arbitrary connections in adbd.
            *error = "adbd does not support arbitrary tcp connections";
            return false;
#endif
        }

        if (fd->get() > 0) {
            disable_tcp_nagle(fd->get());
            if (port) {
                *port = port_value;
            }
            return true;
        }
        return false;
    }

    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (address.starts_with(prefix)) {
            if (!it.second.available) {
                *error = StringPrintf("socket type %s is unavailable on this platform",
                                      it.first.c_str());
                return false;
            }

            fd->reset(network_local_client(&address[prefix.length()], it.second.socket_namespace,
                                           SOCK_STREAM, error));
            return true;
        }
    }

    *error = "unknown socket specification: ";
    *error += address;
    return false;
}

int socket_spec_listen(std::string_view spec, std::string* error, int* resolved_tcp_port) {
    if (spec.starts_with("tcp:")) {
        std::string hostname;
        int port;
        if (!parse_tcp_socket_spec(spec, &hostname, &port, nullptr, error)) {
            return -1;
        }

        int result;
        if (hostname.empty() && gListenAll) {
            result = network_inaddr_any_server(port, SOCK_STREAM, error);
        } else if (tcp_host_is_local(hostname)) {
            result = network_loopback_server(port, SOCK_STREAM, error);
        } else {
            // TODO: Implement me.
            *error = "listening on specified hostname currently unsupported";
            return -1;
        }

        if (result >= 0 && port == 0 && resolved_tcp_port) {
            *resolved_tcp_port = adb_socket_get_local_port(result);
        }
        return result;
    }

    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (spec.starts_with(prefix)) {
            if (!it.second.available) {
                *error = "attempted to listen on unavailable socket type: ";
                *error += spec;
                return -1;
            }

            return network_local_server(&spec[prefix.length()], it.second.socket_namespace,
                                        SOCK_STREAM, error);
        }
    }

    *error = "unknown socket specification:";
    *error += spec;
    return -1;
}
