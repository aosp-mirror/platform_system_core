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
#include <unordered_map>
#include <vector>

#include <android-base/parseint.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "sysdeps.h"

using android::base::StartsWith;
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

bool parse_tcp_socket_spec(const std::string& spec, std::string* hostname, int* port,
                           std::string* error) {
    if (!StartsWith(spec, "tcp:")) {
        *error = StringPrintf("specification is not tcp: '%s'", spec.c_str());
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
        std::string addr = spec.substr(4);
        port_value = -1;

        // FIXME: ParseNetAddress rejects port 0. This currently doesn't hurt, because listening
        //        on an address that isn't 'localhost' is unsupported.
        if (!android::base::ParseNetAddress(addr, &hostname_value, &port_value, nullptr, error)) {
            return false;
        }

        if (port_value == -1) {
            *error = StringPrintf("missing port in specification: '%s'", spec.c_str());
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

static bool tcp_host_is_local(const std::string& hostname) {
    // FIXME
    return hostname.empty() || hostname == "localhost";
}

bool is_socket_spec(const std::string& spec) {
    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            return true;
        }
    }
    return StartsWith(spec, "tcp:");
}

bool is_local_socket_spec(const std::string& spec) {
    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            return true;
        }
    }

    std::string error;
    std::string hostname;
    if (!parse_tcp_socket_spec(spec, &hostname, nullptr, &error)) {
        return false;
    }
    return tcp_host_is_local(hostname);
}

int socket_spec_connect(const std::string& spec, std::string* error) {
    if (StartsWith(spec, "tcp:")) {
        std::string hostname;
        int port;
        if (!parse_tcp_socket_spec(spec, &hostname, &port, error)) {
            return -1;
        }

        int result;
        if (tcp_host_is_local(hostname)) {
            result = network_loopback_client(port, SOCK_STREAM, error);
        } else {
#if ADB_HOST
            result = network_connect(hostname, port, SOCK_STREAM, 0, error);
#else
            // Disallow arbitrary connections in adbd.
            *error = "adbd does not support arbitrary tcp connections";
            return -1;
#endif
        }

        if (result >= 0) {
            disable_tcp_nagle(result);
        }
        return result;
    }

    for (const auto& it : kLocalSocketTypes) {
        std::string prefix = it.first + ":";
        if (StartsWith(spec, prefix.c_str())) {
            if (!it.second.available) {
                *error = StringPrintf("socket type %s is unavailable on this platform",
                                      it.first.c_str());
                return -1;
            }

            return network_local_client(&spec[prefix.length()], it.second.socket_namespace,
                                        SOCK_STREAM, error);
        }
    }

    *error = StringPrintf("unknown socket specification '%s'", spec.c_str());
    return -1;
}

int socket_spec_listen(const std::string& spec, std::string* error, int* resolved_tcp_port) {
    if (StartsWith(spec, "tcp:")) {
        std::string hostname;
        int port;
        if (!parse_tcp_socket_spec(spec, &hostname, &port, error)) {
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
        if (StartsWith(spec, prefix.c_str())) {
            if (!it.second.available) {
                *error = StringPrintf("attempted to listen on unavailable socket type: '%s'",
                                      spec.c_str());
                return -1;
            }

            return network_local_server(&spec[prefix.length()], it.second.socket_namespace,
                                        SOCK_STREAM, error);
        }
    }

    *error = StringPrintf("unknown socket specification '%s'", spec.c_str());
    return -1;
}
