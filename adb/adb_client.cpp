/*
 * Copyright (C) 2015 The Android Open Source Project
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

#define TRACE_TAG ADB

#include "sysdeps.h"
#include "adb_client.h"

#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>
#include <vector>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb_io.h"
#include "adb_utils.h"

static TransportType __adb_transport = kTransportAny;
static const char* __adb_serial = NULL;

static int __adb_server_port = DEFAULT_ADB_PORT;
static const char* __adb_server_name = NULL;

void adb_set_transport(TransportType type, const char* serial)
{
    __adb_transport = type;
    __adb_serial = serial;
}

void adb_get_transport(TransportType* type, const char** serial) {
    if (type) {
        *type = __adb_transport;
    }
    if (serial) {
        *serial = __adb_serial;
    }
}

void adb_set_tcp_specifics(int server_port)
{
    __adb_server_port = server_port;
}

void adb_set_tcp_name(const char* hostname)
{
    __adb_server_name = hostname;
}

static int switch_socket_transport(int fd, std::string* error) {
    std::string service;
    if (__adb_serial) {
        service += "host:transport:";
        service += __adb_serial;
    } else {
        const char* transport_type = "???";
        switch (__adb_transport) {
          case kTransportUsb:
            transport_type = "transport-usb";
            break;
          case kTransportLocal:
            transport_type = "transport-local";
            break;
          case kTransportAny:
            transport_type = "transport-any";
            break;
          case kTransportHost:
            // no switch necessary
            return 0;
        }
        service += "host:";
        service += transport_type;
    }

    if (!SendProtocolString(fd, service)) {
        *error = perror_str("write failure during connection");
        adb_close(fd);
        return -1;
    }
    D("Switch transport in progress");

    if (!adb_status(fd, error)) {
        adb_close(fd);
        D("Switch transport failed: %s", error->c_str());
        return -1;
    }
    D("Switch transport success");
    return 0;
}

bool adb_status(int fd, std::string* error) {
    char buf[5];
    if (!ReadFdExactly(fd, buf, 4)) {
        *error = perror_str("protocol fault (couldn't read status)");
        return false;
    }

    if (!memcmp(buf, "OKAY", 4)) {
        return true;
    }

    if (memcmp(buf, "FAIL", 4)) {
        *error = android::base::StringPrintf("protocol fault (status %02x %02x %02x %02x?!)",
                                             buf[0], buf[1], buf[2], buf[3]);
        return false;
    }

    ReadProtocolString(fd, error, error);
    return false;
}

int _adb_connect(const std::string& service, std::string* error) {
    D("_adb_connect: %s", service.c_str());
    if (service.empty() || service.size() > MAX_PAYLOAD_V1) {
        *error = android::base::StringPrintf("bad service name length (%zd)",
                                             service.size());
        return -1;
    }

    int fd;
    std::string reason;
    if (__adb_server_name) {
        fd = network_connect(__adb_server_name, __adb_server_port, SOCK_STREAM, 0, &reason);
        if (fd == -1) {
            *error = android::base::StringPrintf("can't connect to %s:%d: %s",
                                                 __adb_server_name, __adb_server_port,
                                                 reason.c_str());
            return -2;
        }
    } else {
        fd = network_loopback_client(__adb_server_port, SOCK_STREAM, &reason);
        if (fd == -1) {
            *error = android::base::StringPrintf("cannot connect to daemon: %s",
                                                 reason.c_str());
            return -2;
        }
    }

    if ((memcmp(&service[0],"host",4) != 0 || service == "host:reconnect") &&
        switch_socket_transport(fd, error)) {
        return -1;
    }

    if (!SendProtocolString(fd, service)) {
        *error = perror_str("write failure during connection");
        adb_close(fd);
        return -1;
    }

    if (service != "reconnect") {
        if (!adb_status(fd, error)) {
            adb_close(fd);
            return -1;
        }
    }

    D("_adb_connect: return fd %d", fd);
    return fd;
}

int adb_connect(const std::string& service, std::string* error) {
    // first query the adb server's version
    int fd = _adb_connect("host:version", error);

    D("adb_connect: service %s", service.c_str());
    if (fd == -2 && __adb_server_name) {
        fprintf(stderr,"** Cannot start server on remote host\n");
        // error is the original network connection error
        return fd;
    } else if (fd == -2) {
        fprintf(stdout,"* daemon not running. starting it now on port %d *\n",
                __adb_server_port);
    start_server:
        if (launch_server(__adb_server_port)) {
            fprintf(stderr,"* failed to start daemon *\n");
            // launch_server() has already printed detailed error info, so just
            // return a generic error string about the overall adb_connect()
            // that the caller requested.
            *error = "cannot connect to daemon";
            return -1;
        } else {
            fprintf(stdout,"* daemon started successfully *\n");
        }
        /* give the server some time to start properly and detect devices */
        adb_sleep_ms(3000);
        // fall through to _adb_connect
    } else {
        // If a server is already running, check its version matches.
        int version = ADB_SERVER_VERSION - 1;

        // If we have a file descriptor, then parse version result.
        if (fd >= 0) {
            std::string version_string;
            if (!ReadProtocolString(fd, &version_string, error)) {
                adb_close(fd);
                return -1;
            }

            ReadOrderlyShutdown(fd);
            adb_close(fd);

            if (sscanf(&version_string[0], "%04x", &version) != 1) {
                *error = android::base::StringPrintf("cannot parse version string: %s",
                                                     version_string.c_str());
                return -1;
            }
        } else {
            // If fd is -1 check for "unknown host service" which would
            // indicate a version of adb that does not support the
            // version command, in which case we should fall-through to kill it.
            if (*error != "unknown host service") {
                return fd;
            }
        }

        if (version != ADB_SERVER_VERSION) {
            printf("adb server version (%d) doesn't match this client (%d); killing...\n",
                   version, ADB_SERVER_VERSION);
            fd = _adb_connect("host:kill", error);
            if (fd >= 0) {
                ReadOrderlyShutdown(fd);
                adb_close(fd);
            } else {
                // If we couldn't connect to the server or had some other error,
                // report it, but still try to start the server.
                fprintf(stderr, "error: %s\n", error->c_str());
            }

            /* XXX can we better detect its death? */
            adb_sleep_ms(2000);
            goto start_server;
        }
    }

    // if the command is start-server, we are done.
    if (service == "host:start-server") {
        return 0;
    }

    fd = _adb_connect(service, error);
    if (fd == -1) {
        D("_adb_connect error: %s", error->c_str());
    } else if(fd == -2) {
        fprintf(stderr,"** daemon still not running\n");
    }
    D("adb_connect: return fd %d", fd);

    return fd;
}


bool adb_command(const std::string& service) {
    std::string error;
    int fd = adb_connect(service, &error);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", error.c_str());
        return false;
    }

    if (!adb_status(fd, &error)) {
        fprintf(stderr, "error: %s\n", error.c_str());
        adb_close(fd);
        return false;
    }

    ReadOrderlyShutdown(fd);
    adb_close(fd);
    return true;
}

bool adb_query(const std::string& service, std::string* result, std::string* error) {
    D("adb_query: %s", service.c_str());
    int fd = adb_connect(service, error);
    if (fd < 0) {
        return false;
    }

    result->clear();
    if (!ReadProtocolString(fd, result, error)) {
        adb_close(fd);
        return false;
    }

    ReadOrderlyShutdown(fd);
    adb_close(fd);
    return true;
}

std::string format_host_command(const char* command, TransportType type, const char* serial) {
    if (serial) {
        return android::base::StringPrintf("host-serial:%s:%s", serial, command);
    }

    const char* prefix = "host";
    if (type == kTransportUsb) {
        prefix = "host-usb";
    } else if (type == kTransportLocal) {
        prefix = "host-local";
    }
    return android::base::StringPrintf("%s:%s", prefix, command);
}

bool adb_get_feature_set(FeatureSet* feature_set, std::string* error) {
    std::string result;
    if (adb_query(format_host_command("features", __adb_transport, __adb_serial), &result, error)) {
        *feature_set = StringToFeatureSet(result);
        return true;
    }
    feature_set->clear();
    return false;
}
