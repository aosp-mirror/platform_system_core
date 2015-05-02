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

#define TRACE_TAG TRACE_ADB

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

#include <base/stringprintf.h>
#include <base/strings.h>

#include "adb_io.h"

static transport_type __adb_transport = kTransportAny;
static const char* __adb_serial = NULL;

static int __adb_server_port = DEFAULT_ADB_PORT;
static const char* __adb_server_name = NULL;

static std::string perror_str(const char* msg) {
    return android::base::StringPrintf("%s: %s", msg, strerror(errno));
}

static bool ReadProtocolString(int fd, std::string* s, std::string* error) {
    char buf[5];
    if (!ReadFdExactly(fd, buf, 4)) {
        *error = perror_str("protocol fault (couldn't read status length)");
        return false;
    }
    buf[4] = 0;

    unsigned long len = strtoul(buf, 0, 16);
    s->resize(len, '\0');
    if (!ReadFdExactly(fd, &(*s)[0], len)) {
        *error = perror_str("protocol fault (couldn't read status message)");
        return false;
    }

    return true;
}

void adb_set_transport(transport_type type, const char* serial)
{
    __adb_transport = type;
    __adb_serial = serial;
}

void adb_set_tcp_specifics(int server_port)
{
    __adb_server_port = server_port;
}

void adb_set_tcp_name(const char* hostname)
{
    __adb_server_name = hostname;
}

int adb_get_emulator_console_port() {
    if (__adb_serial) {
        // The user specified a serial number; is it an emulator?
        int port;
        return (sscanf(__adb_serial, "emulator-%d", &port) == 1) ? port : -1;
    }

    // No specific device was given, so get the list of connected
    // devices and search for emulators. If there's one, we'll
    // take it. If there are more than one, that's an error.
    std::string devices;
    std::string error;
    if (!adb_query("host:devices", &devices, &error)) {
        printf("no emulator connected: %s\n", error.c_str());
        return -1;
    }

    int port;
    size_t emulator_count = 0;
    for (auto& device : android::base::Split(devices, "\n")) {
        if (sscanf(device.c_str(), "emulator-%d", &port) == 1) {
            if (++emulator_count > 1) {
                return -2;
            }
        }
    }
    if (emulator_count == 0) return -1;
    return port;
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
    D("Switch transport in progress\n");

    if (!adb_status(fd, error)) {
        adb_close(fd);
        D("Switch transport failed: %s\n", error->c_str());
        return -1;
    }
    D("Switch transport success\n");
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
    D("_adb_connect: %s\n", service.c_str());
    if (service.empty() || service.size() > 1024) {
        *error = android::base::StringPrintf("bad service name length (%d)",
                                             static_cast<int>(service.size()));
        return -1;
    }

    int fd;
    if (__adb_server_name) {
        fd = socket_network_client(__adb_server_name, __adb_server_port, SOCK_STREAM);
    } else {
        fd = socket_loopback_client(__adb_server_port, SOCK_STREAM);
    }
    if (fd < 0) {
        *error = perror_str("cannot connect to daemon");
        return -2;
    }

    if (memcmp(&service[0],"host",4) != 0 && switch_socket_transport(fd, error)) {
        return -1;
    }

    if(!SendProtocolString(fd, service)) {
        *error = perror_str("write failure during connection");
        adb_close(fd);
        return -1;
    }

    if (!adb_status(fd, error)) {
        adb_close(fd);
        return -1;
    }

    D("_adb_connect: return fd %d\n", fd);
    return fd;
}

int adb_connect(const std::string& service, std::string* error) {
    // first query the adb server's version
    int fd = _adb_connect("host:version", error);

    D("adb_connect: service %s\n", service.c_str());
    if (fd == -2 && __adb_server_name) {
        fprintf(stderr,"** Cannot start server on remote host\n");
        return fd;
    } else if (fd == -2) {
        fprintf(stdout,"* daemon not running. starting it now on port %d *\n",
                __adb_server_port);
    start_server:
        if (launch_server(__adb_server_port)) {
            fprintf(stderr,"* failed to start daemon *\n");
            return -1;
        } else {
            fprintf(stdout,"* daemon started successfully *\n");
        }
        /* give the server some time to start properly and detect devices */
        adb_sleep_ms(3000);
        // fall through to _adb_connect
    } else {
        // if server was running, check its version to make sure it is not out of date
        int version = ADB_SERVER_VERSION - 1;

        // if we have a file descriptor, then parse version result
        if (fd >= 0) {
            std::string version_string;
            if (!ReadProtocolString(fd, &version_string, error)) {
                goto error;
            }

            adb_close(fd);

            if (sscanf(&version_string[0], "%04x", &version) != 1) {
                goto error;
            }
        } else {
            // if fd is -1, then check for "unknown host service",
            // which would indicate a version of adb that does not support the version command
            if (*error == "unknown host service") {
                return fd;
            }
        }

        if (version != ADB_SERVER_VERSION) {
            printf("adb server is out of date.  killing...\n");
            fd = _adb_connect("host:kill", error);
            adb_close(fd);

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
    D("adb_connect: return fd %d\n", fd);

    return fd;
error:
    adb_close(fd);
    return -1;
}


int adb_command(const std::string& service, std::string* error) {
    int fd = adb_connect(service, error);
    if (fd < 0) {
        fprintf(stderr, "error: %s\n", error->c_str());
        return -1;
    }

    if (!adb_status(fd, error)) {
        adb_close(fd);
        return -1;
    }

    return 0;
}

bool adb_query(const std::string& service, std::string* result, std::string* error) {
    D("adb_query: %s\n", service.c_str());
    int fd = adb_connect(service, error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error->c_str());
        return 0;
    }

    result->clear();
    if (!ReadProtocolString(fd, result, error)) {
        adb_close(fd);
        return false;
    }
    return true;
}
