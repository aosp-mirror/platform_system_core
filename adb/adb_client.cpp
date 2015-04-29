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

#include "adb_io.h"

static transport_type __adb_transport = kTransportAny;
static const char* __adb_serial = NULL;

static int __adb_server_port = DEFAULT_ADB_PORT;
static const char* __adb_server_name = NULL;

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

int  adb_get_emulator_console_port(void)
{
    const char*   serial = __adb_serial;
    int           port;

    if (serial == NULL) {
        /* if no specific device was specified, we need to look at */
        /* the list of connected devices, and extract an emulator  */
        /* name from it. two emulators is an error                 */
        std::string error;
        char*  tmp = adb_query("host:devices", &error);
        char*  p   = tmp;
        if (!tmp) {
            printf("no emulator connected: %s\n", error.c_str());
            return -1;
        }
        while (*p) {
            char*  q = strchr(p, '\n');
            if (q != NULL)
                *q++ = 0;
            else
                q = p + strlen(p);

            if (!memcmp(p, LOCAL_CLIENT_PREFIX, sizeof(LOCAL_CLIENT_PREFIX)-1)) {
                if (serial != NULL) {  /* more than one emulator listed */
                    free(tmp);
                    return -2;
                }
                serial = p;
            }

            p = q;
        }
        free(tmp);

        if (serial == NULL)
            return -1;  /* no emulator found */
    }
    else {
        if (memcmp(serial, LOCAL_CLIENT_PREFIX, sizeof(LOCAL_CLIENT_PREFIX)-1) != 0)
            return -1;  /* not an emulator */
    }

    serial += sizeof(LOCAL_CLIENT_PREFIX)-1;
    port    = strtol(serial, NULL, 10);
    return port;
}

std::string perror_str(const char* msg) {
    return android::base::StringPrintf("%s: %s", msg, strerror(errno));
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

    char tmp[5];
    snprintf(tmp, sizeof(tmp), "%04zx", service.size());
    if (!WriteFdExactly(fd, tmp, 4) || !WriteFdExactly(fd, service.c_str(), service.size())) {
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

    if (!ReadFdExactly(fd, buf, 4)) {
        *error = perror_str("protocol fault (couldn't read status length)");
        return false;
    }
    buf[4] = 0;

    unsigned long len = strtoul(buf, 0, 16);
    error->resize(len + 1, '\0'); // Ensure NUL-termination.
    if (!ReadFdExactly(fd, &(*error)[0], len)) {
        *error = perror_str("protocol fault (couldn't read status message)");
    }
    return false;
}

int _adb_connect(const char *service, std::string* error) {
    char tmp[5];
    int fd;

    D("_adb_connect: %s\n", service);
    size_t len = strlen(service);
    if ((len < 1) || (len > 1024)) {
        *error = android::base::StringPrintf("service name too long (%d)", static_cast<int>(len));
        return -1;
    }
    snprintf(tmp, sizeof tmp, "%04zx", len);

    if (__adb_server_name)
        fd = socket_network_client(__adb_server_name, __adb_server_port, SOCK_STREAM);
    else
        fd = socket_loopback_client(__adb_server_port, SOCK_STREAM);

    if(fd < 0) {
        *error = perror_str("cannot connect to daemon");
        return -2;
    }

    if (memcmp(service,"host",4) != 0 && switch_socket_transport(fd, error)) {
        return -1;
    }

    if(!WriteFdExactly(fd, tmp, 4) || !WriteFdExactly(fd, service, len)) {
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

int adb_connect(const char* service, std::string* error) {
    // first query the adb server's version
    int fd = _adb_connect("host:version", error);

    D("adb_connect: service %s\n", service);
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
        char buf[100];
        size_t n;
        int version = ADB_SERVER_VERSION - 1;

        // if we have a file descriptor, then parse version result
        if (fd >= 0) {
            if(!ReadFdExactly(fd, buf, 4)) goto error;

            buf[4] = 0;
            n = strtoul(buf, 0, 16);
            if(n > sizeof(buf)) goto error;
            if(!ReadFdExactly(fd, buf, n)) goto error;
            adb_close(fd);

            if (sscanf(buf, "%04x", &version) != 1) goto error;
        } else {
            // if fd is -1, then check for "unknown host service",
            // which would indicate a version of adb that does not support the version command
            if (*error == "unknown host service") {
                return fd;
            }
        }

        if(version != ADB_SERVER_VERSION) {
            printf("adb server is out of date.  killing...\n");
            fd = _adb_connect("host:kill", error);
            adb_close(fd);

            /* XXX can we better detect its death? */
            adb_sleep_ms(2000);
            goto start_server;
        }
    }

    // if the command is start-server, we are done.
    if (!strcmp(service, "host:start-server")) {
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


int adb_command(const char* service, std::string* error) {
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

char* adb_query(const char* service, std::string* error) {
    char buf[5];
    unsigned long n;
    char* tmp;

    D("adb_query: %s\n", service);
    int fd = adb_connect(service, error);
    if (fd < 0) {
        fprintf(stderr,"error: %s\n", error->c_str());
        return 0;
    }

    if (!ReadFdExactly(fd, buf, 4)) goto oops;

    buf[4] = 0;
    n = strtoul(buf, 0, 16);
    // TODO: given that we just read a 4-byte hex length 0x????, why the test?
    if (n >= 0xffff) {
        *error = "reply is too long (>= 64KiB)";
        goto oops;
    }

    tmp = reinterpret_cast<char*>(malloc(n + 1));
    if(tmp == 0) goto oops;

    if(!ReadFdExactly(fd, tmp, n) == 0) {
        tmp[n] = 0;
        adb_close(fd);
        return tmp;
    }
    free(tmp);

oops:
    adb_close(fd);
    return 0;
}
