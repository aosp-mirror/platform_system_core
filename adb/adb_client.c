#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <zipfile/zipfile.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb_client.h"

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
        char*  tmp = adb_query("host:devices");
        char*  p   = tmp;
        if(!tmp) {
            printf("no emulator connected\n");
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

static char __adb_error[256] = { 0 };

const char *adb_error(void)
{
    return __adb_error;
}

static int switch_socket_transport(int fd)
{
    char service[64];
    char tmp[5];
    int len;

    if (__adb_serial)
        snprintf(service, sizeof service, "host:transport:%s", __adb_serial);
    else {
        char* transport_type = "???";

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
                break;
        }

        snprintf(service, sizeof service, "host:%s", transport_type);
    }
    len = strlen(service);
    snprintf(tmp, sizeof tmp, "%04x", len);

    if(writex(fd, tmp, 4) || writex(fd, service, len)) {
        strcpy(__adb_error, "write failure during connection");
        adb_close(fd);
        return -1;
    }
    D("Switch transport in progress\n");

    if(adb_status(fd)) {
        adb_close(fd);
        D("Switch transport failed\n");
        return -1;
    }
    D("Switch transport success\n");
    return 0;
}

int adb_status(int fd)
{
    unsigned char buf[5];
    unsigned len;

    if(readx(fd, buf, 4)) {
        strcpy(__adb_error, "protocol fault (no status)");
        return -1;
    }

    if(!memcmp(buf, "OKAY", 4)) {
        return 0;
    }

    if(memcmp(buf, "FAIL", 4)) {
        sprintf(__adb_error,
                "protocol fault (status %02x %02x %02x %02x?!)",
                buf[0], buf[1], buf[2], buf[3]);
        return -1;
    }

    if(readx(fd, buf, 4)) {
        strcpy(__adb_error, "protocol fault (status len)");
        return -1;
    }
    buf[4] = 0;
    len = strtoul((char*)buf, 0, 16);
    if(len > 255) len = 255;
    if(readx(fd, __adb_error, len)) {
        strcpy(__adb_error, "protocol fault (status read)");
        return -1;
    }
    __adb_error[len] = 0;
    return -1;
}

int _adb_connect(const char *service)
{
    char tmp[5];
    int len;
    int fd;

    D("_adb_connect: %s\n", service);
    len = strlen(service);
    if((len < 1) || (len > 1024)) {
        strcpy(__adb_error, "service name too long");
        return -1;
    }
    snprintf(tmp, sizeof tmp, "%04x", len);

    if (__adb_server_name)
        fd = socket_network_client(__adb_server_name, __adb_server_port, SOCK_STREAM);
    else
        fd = socket_loopback_client(__adb_server_port, SOCK_STREAM);

    if(fd < 0) {
        strcpy(__adb_error, "cannot connect to daemon");
        return -2;
    }

    if (memcmp(service,"host",4) != 0 && switch_socket_transport(fd)) {
        return -1;
    }

    if(writex(fd, tmp, 4) || writex(fd, service, len)) {
        strcpy(__adb_error, "write failure during connection");
        adb_close(fd);
        return -1;
    }

    if(adb_status(fd)) {
        adb_close(fd);
        return -1;
    }

    D("_adb_connect: return fd %d\n", fd);
    return fd;
}

int adb_connect(const char *service)
{
    // first query the adb server's version
    int fd = _adb_connect("host:version");

    D("adb_connect: service %s\n", service);
    if(fd == -2 && __adb_server_name) {
        fprintf(stderr,"** Cannot start server on remote host\n");
        return fd;
    } else if(fd == -2) {
        fprintf(stdout,"* daemon not running. starting it now on port %d *\n",
                __adb_server_port);
    start_server:
        if(launch_server(__adb_server_port)) {
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
        if(fd >= 0) {
            if(readx(fd, buf, 4)) goto error;

            buf[4] = 0;
            n = strtoul(buf, 0, 16);
            if(n > sizeof(buf)) goto error;
            if(readx(fd, buf, n)) goto error;
            adb_close(fd);

            if (sscanf(buf, "%04x", &version) != 1) goto error;
        } else {
            // if fd is -1, then check for "unknown host service",
            // which would indicate a version of adb that does not support the version command
            if (strcmp(__adb_error, "unknown host service") != 0)
                return fd;
        }

        if(version != ADB_SERVER_VERSION) {
            printf("adb server is out of date.  killing...\n");
            fd = _adb_connect("host:kill");
            adb_close(fd);

            /* XXX can we better detect its death? */
            adb_sleep_ms(2000);
            goto start_server;
        }
    }

    // if the command is start-server, we are done.
    if (!strcmp(service, "host:start-server"))
        return 0;

    fd = _adb_connect(service);
    if(fd == -2) {
        fprintf(stderr,"** daemon still not running\n");
    }
    D("adb_connect: return fd %d\n", fd);

    return fd;
error:
    adb_close(fd);
    return -1;
}


int adb_command(const char *service)
{
    int fd = adb_connect(service);
    if(fd < 0) {
        return -1;
    }

    if(adb_status(fd)) {
        adb_close(fd);
        return -1;
    }

    return 0;
}

char *adb_query(const char *service)
{
    char buf[5];
    unsigned n;
    char *tmp;

    D("adb_query: %s\n", service);
    int fd = adb_connect(service);
    if(fd < 0) {
        fprintf(stderr,"error: %s\n", __adb_error);
        return 0;
    }

    if(readx(fd, buf, 4)) goto oops;

    buf[4] = 0;
    n = strtoul(buf, 0, 16);
    if(n > 1024) goto oops;

    tmp = malloc(n + 1);
    if(tmp == 0) goto oops;

    if(readx(fd, tmp, n) == 0) {
        tmp[n] = 0;
        adb_close(fd);
        return tmp;
    }
    free(tmp);

oops:
    adb_close(fd);
    return 0;
}
