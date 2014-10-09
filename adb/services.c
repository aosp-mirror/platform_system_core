/*
 * Copyright (C) 2007 The Android Open Source Project
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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_SERVICES
#include "adb.h"
#include "file_sync_service.h"

#if ADB_HOST
#  ifndef HAVE_WINSOCK
#    include <netinet/in.h>
#    include <netdb.h>
#    include <sys/ioctl.h>
#  endif
#else
#  include <cutils/android_reboot.h>
#  include <cutils/properties.h>
#endif

typedef struct stinfo stinfo;

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};


void *service_bootstrap_func(void *x)
{
    stinfo *sti = x;
    sti->func(sti->fd, sti->cookie);
    free(sti);
    return 0;
}

#if !ADB_HOST

void restart_root_service(int fd, void *cookie)
{
    char buf[100];
    char value[PROPERTY_VALUE_MAX];

    if (getuid() == 0) {
        snprintf(buf, sizeof(buf), "adbd is already running as root\n");
        writex(fd, buf, strlen(buf));
        adb_close(fd);
    } else {
        property_get("ro.debuggable", value, "");
        if (strcmp(value, "1") != 0) {
            snprintf(buf, sizeof(buf), "adbd cannot run as root in production builds\n");
            writex(fd, buf, strlen(buf));
            adb_close(fd);
            return;
        }

        property_set("service.adb.root", "1");
        snprintf(buf, sizeof(buf), "restarting adbd as root\n");
        writex(fd, buf, strlen(buf));
        adb_close(fd);
    }
}

void restart_tcp_service(int fd, void *cookie)
{
    char buf[100];
    char value[PROPERTY_VALUE_MAX];
    int port = (int) (uintptr_t) cookie;

    if (port <= 0) {
        snprintf(buf, sizeof(buf), "invalid port\n");
        writex(fd, buf, strlen(buf));
        adb_close(fd);
        return;
    }

    snprintf(value, sizeof(value), "%d", port);
    property_set("service.adb.tcp.port", value);
    snprintf(buf, sizeof(buf), "restarting in TCP mode port: %d\n", port);
    writex(fd, buf, strlen(buf));
    adb_close(fd);
}

void restart_usb_service(int fd, void *cookie)
{
    char buf[100];

    property_set("service.adb.tcp.port", "0");
    snprintf(buf, sizeof(buf), "restarting in USB mode\n");
    writex(fd, buf, strlen(buf));
    adb_close(fd);
}

void reboot_service(int fd, void *arg)
{
    char buf[100];
    char property_val[PROPERTY_VALUE_MAX];
    int ret;

    sync();

    ret = snprintf(property_val, sizeof(property_val), "reboot,%s", (char *) arg);
    if (ret >= (int) sizeof(property_val)) {
        snprintf(buf, sizeof(buf), "reboot string too long. length=%d\n", ret);
        writex(fd, buf, strlen(buf));
        goto cleanup;
    }

    ret = property_set(ANDROID_RB_PROPERTY, property_val);
    if (ret < 0) {
        snprintf(buf, sizeof(buf), "reboot failed: %d\n", ret);
        writex(fd, buf, strlen(buf));
        goto cleanup;
    }
    // Don't return early. Give the reboot command time to take effect
    // to avoid messing up scripts which do "adb reboot && adb wait-for-device"
    while(1) { pause(); }
cleanup:
    free(arg);
    adb_close(fd);
}

void reverse_service(int fd, void* arg)
{
    const char* command = arg;

    if (handle_forward_request(command, kTransportAny, NULL, fd) < 0) {
        sendfailmsg(fd, "not a reverse forwarding command");
    }
    free(arg);
    adb_close(fd);
}

#endif

static int create_service_thread(void (*func)(int, void *), void *cookie)
{
    stinfo *sti;
    adb_thread_t t;
    int s[2];

    if(adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return -1;
    }

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = func;
    sti->cookie = cookie;
    sti->fd = s[1];

    if(adb_thread_create( &t, service_bootstrap_func, sti)){
        free(sti);
        adb_close(s[0]);
        adb_close(s[1]);
        printf("cannot create service thread\n");
        return -1;
    }

    D("service thread started, %d:%d\n",s[0], s[1]);
    return s[0];
}

#if !ADB_HOST

static void init_subproc_child()
{
    setsid();

    // Set OOM score adjustment to prevent killing
    int fd = adb_open("/proc/self/oom_score_adj", O_WRONLY | O_CLOEXEC);
    if (fd >= 0) {
        adb_write(fd, "0", 1);
        adb_close(fd);
    } else {
       D("adb: unable to update oom_score_adj\n");
    }
}

static int create_subproc_pty(const char *cmd, const char *arg0, const char *arg1, pid_t *pid)
{
    D("create_subproc_pty(cmd=%s, arg0=%s, arg1=%s)\n", cmd, arg0, arg1);
#ifdef HAVE_WIN32_PROC
    fprintf(stderr, "error: create_subproc_pty not implemented on Win32 (%s %s %s)\n", cmd, arg0, arg1);
    return -1;
#else /* !HAVE_WIN32_PROC */
    int ptm;

    ptm = unix_open("/dev/ptmx", O_RDWR | O_CLOEXEC); // | O_NOCTTY);
    if(ptm < 0){
        printf("[ cannot open /dev/ptmx - %s ]\n",strerror(errno));
        return -1;
    }

    char devname[64];
    if(grantpt(ptm) || unlockpt(ptm) || ptsname_r(ptm, devname, sizeof(devname)) != 0) {
        printf("[ trouble with /dev/ptmx - %s ]\n", strerror(errno));
        adb_close(ptm);
        return -1;
    }

    *pid = fork();
    if(*pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        adb_close(ptm);
        return -1;
    }

    if (*pid == 0) {
        init_subproc_child();

        int pts = unix_open(devname, O_RDWR | O_CLOEXEC);
        if (pts < 0) {
            fprintf(stderr, "child failed to open pseudo-term slave: %s\n", devname);
            exit(-1);
        }

        dup2(pts, STDIN_FILENO);
        dup2(pts, STDOUT_FILENO);
        dup2(pts, STDERR_FILENO);

        adb_close(pts);
        adb_close(ptm);

        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        return ptm;
    }
#endif /* !HAVE_WIN32_PROC */
}

static int create_subproc_raw(const char *cmd, const char *arg0, const char *arg1, pid_t *pid)
{
    D("create_subproc_raw(cmd=%s, arg0=%s, arg1=%s)\n", cmd, arg0, arg1);
#ifdef HAVE_WIN32_PROC
    fprintf(stderr, "error: create_subproc_raw not implemented on Win32 (%s %s %s)\n", cmd, arg0, arg1);
    return -1;
#else /* !HAVE_WIN32_PROC */

    // 0 is parent socket, 1 is child socket
    int sv[2];
    if (unix_socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        printf("[ cannot create socket pair - %s ]\n", strerror(errno));
        return -1;
    }

    *pid = fork();
    if (*pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        adb_close(sv[0]);
        adb_close(sv[1]);
        return -1;
    }

    if (*pid == 0) {
        adb_close(sv[0]);
        init_subproc_child();

        dup2(sv[1], STDIN_FILENO);
        dup2(sv[1], STDOUT_FILENO);
        dup2(sv[1], STDERR_FILENO);

        adb_close(sv[1]);

        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        adb_close(sv[1]);
        return sv[0];
    }
#endif /* !HAVE_WIN32_PROC */
}
#endif  /* !ABD_HOST */

#if ADB_HOST
#define SHELL_COMMAND "/bin/sh"
#else
#define SHELL_COMMAND "/system/bin/sh"
#endif

#if !ADB_HOST
static void subproc_waiter_service(int fd, void *cookie)
{
    pid_t pid = (pid_t) (uintptr_t) cookie;

    D("entered. fd=%d of pid=%d\n", fd, pid);
    for (;;) {
        int status;
        pid_t p = waitpid(pid, &status, 0);
        if (p == pid) {
            D("fd=%d, post waitpid(pid=%d) status=%04x\n", fd, p, status);
            if (WIFSIGNALED(status)) {
                D("*** Killed by signal %d\n", WTERMSIG(status));
                break;
            } else if (!WIFEXITED(status)) {
                D("*** Didn't exit!!. status %d\n", status);
                break;
            } else if (WEXITSTATUS(status) >= 0) {
                D("*** Exit code %d\n", WEXITSTATUS(status));
                break;
            }
         }
    }
    D("shell exited fd=%d of pid=%d err=%d\n", fd, pid, errno);
    if (SHELL_EXIT_NOTIFY_FD >=0) {
      int res;
      res = writex(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd));
      D("notified shell exit via fd=%d for pid=%d res=%d errno=%d\n",
        SHELL_EXIT_NOTIFY_FD, pid, res, errno);
    }
}

static int create_subproc_thread(const char *name, const subproc_mode mode)
{
    stinfo *sti;
    adb_thread_t t;
    int ret_fd;
    pid_t pid = -1;

    const char *arg0, *arg1;
    if (name == 0 || *name == 0) {
        arg0 = "-"; arg1 = 0;
    } else {
        arg0 = "-c"; arg1 = name;
    }

    switch (mode) {
    case SUBPROC_PTY:
        ret_fd = create_subproc_pty(SHELL_COMMAND, arg0, arg1, &pid);
        break;
    case SUBPROC_RAW:
        ret_fd = create_subproc_raw(SHELL_COMMAND, arg0, arg1, &pid);
        break;
    default:
        fprintf(stderr, "invalid subproc_mode %d\n", mode);
        return -1;
    }
    D("create_subproc ret_fd=%d pid=%d\n", ret_fd, pid);

    sti = malloc(sizeof(stinfo));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*) (uintptr_t) pid;
    sti->fd = ret_fd;

    if (adb_thread_create(&t, service_bootstrap_func, sti)) {
        free(sti);
        adb_close(ret_fd);
        fprintf(stderr, "cannot create service thread\n");
        return -1;
    }

    D("service thread started, fd=%d pid=%d\n", ret_fd, pid);
    return ret_fd;
}
#endif

int service_to_fd(const char *name)
{
    int ret = -1;

    if(!strncmp(name, "tcp:", 4)) {
        int port = atoi(name + 4);
        name = strchr(name + 4, ':');
        if(name == 0) {
            ret = socket_loopback_client(port, SOCK_STREAM);
            if (ret >= 0)
                disable_tcp_nagle(ret);
        } else {
#if ADB_HOST
            ret = socket_network_client(name + 1, port, SOCK_STREAM);
#else
            return -1;
#endif
        }
#ifndef HAVE_WINSOCK   /* winsock doesn't implement unix domain sockets */
    } else if(!strncmp(name, "local:", 6)) {
        ret = socket_local_client(name + 6,
                ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    } else if(!strncmp(name, "localreserved:", 14)) {
        ret = socket_local_client(name + 14,
                ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_STREAM);
    } else if(!strncmp(name, "localabstract:", 14)) {
        ret = socket_local_client(name + 14,
                ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM);
    } else if(!strncmp(name, "localfilesystem:", 16)) {
        ret = socket_local_client(name + 16,
                ANDROID_SOCKET_NAMESPACE_FILESYSTEM, SOCK_STREAM);
#endif
#if !ADB_HOST
    } else if(!strncmp("dev:", name, 4)) {
        ret = unix_open(name + 4, O_RDWR | O_CLOEXEC);
    } else if(!strncmp(name, "framebuffer:", 12)) {
        ret = create_service_thread(framebuffer_service, 0);
    } else if (!strncmp(name, "jdwp:", 5)) {
        ret = create_jdwp_connection_fd(atoi(name+5));
    } else if(!HOST && !strncmp(name, "shell:", 6)) {
        ret = create_subproc_thread(name + 6, SUBPROC_PTY);
    } else if(!HOST && !strncmp(name, "exec:", 5)) {
        ret = create_subproc_thread(name + 5, SUBPROC_RAW);
    } else if(!strncmp(name, "sync:", 5)) {
        ret = create_service_thread(file_sync_service, NULL);
    } else if(!strncmp(name, "remount:", 8)) {
        ret = create_service_thread(remount_service, NULL);
    } else if(!strncmp(name, "reboot:", 7)) {
        void* arg = strdup(name + 7);
        if (arg == NULL) return -1;
        ret = create_service_thread(reboot_service, arg);
    } else if(!strncmp(name, "root:", 5)) {
        ret = create_service_thread(restart_root_service, NULL);
    } else if(!strncmp(name, "backup:", 7)) {
        char* arg = strdup(name + 7);
        if (arg == NULL) return -1;
        char* c = arg;
        for (; *c != '\0'; c++) {
            if (*c == ':')
                *c = ' ';
        }
        char* cmd;
        if (asprintf(&cmd, "/system/bin/bu backup %s", arg) != -1) {
            ret = create_subproc_thread(cmd, SUBPROC_RAW);
            free(cmd);
        }
        free(arg);
    } else if(!strncmp(name, "restore:", 8)) {
        ret = create_subproc_thread("/system/bin/bu restore", SUBPROC_RAW);
    } else if(!strncmp(name, "tcpip:", 6)) {
        int port;
        if (sscanf(name + 6, "%d", &port) == 0) {
            port = 0;
        }
        ret = create_service_thread(restart_tcp_service, (void *) (uintptr_t) port);
    } else if(!strncmp(name, "usb:", 4)) {
        ret = create_service_thread(restart_usb_service, NULL);
    } else if (!strncmp(name, "reverse:", 8)) {
        char* cookie = strdup(name + 8);
        if (cookie == NULL) {
            ret = -1;
        } else {
            ret = create_service_thread(reverse_service, cookie);
            if (ret < 0) {
                free(cookie);
            }
        }
    } else if(!strncmp(name, "disable-verity:", 15)) {
        ret = create_service_thread(disable_verity_service, NULL);
#endif
    }
    if (ret >= 0) {
        close_on_exec(ret);
    }
    return ret;
}

#if ADB_HOST
struct state_info {
    transport_type transport;
    char* serial;
    int state;
};

static void wait_for_state(int fd, void* cookie)
{
    struct state_info* sinfo = cookie;
    char* err = "unknown error";

    D("wait_for_state %d\n", sinfo->state);

    atransport *t = acquire_one_transport(sinfo->state, sinfo->transport, sinfo->serial, &err);
    if(t != 0) {
        writex(fd, "OKAY", 4);
    } else {
        sendfailmsg(fd, err);
    }

    if (sinfo->serial)
        free(sinfo->serial);
    free(sinfo);
    adb_close(fd);
    D("wait_for_state is done\n");
}

static void connect_device(char* host, char* buffer, int buffer_size)
{
    int port, fd;
    char* portstr = strchr(host, ':');
    char hostbuf[100];
    char serial[100];
    int ret;

    strncpy(hostbuf, host, sizeof(hostbuf) - 1);
    if (portstr) {
        if (portstr - host >= (ptrdiff_t)sizeof(hostbuf)) {
            snprintf(buffer, buffer_size, "bad host name %s", host);
            return;
        }
        // zero terminate the host at the point we found the colon
        hostbuf[portstr - host] = 0;
        if (sscanf(portstr + 1, "%d", &port) == 0) {
            snprintf(buffer, buffer_size, "bad port number %s", portstr);
            return;
        }
    } else {
        port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    }

    snprintf(serial, sizeof(serial), "%s:%d", hostbuf, port);

    fd = socket_network_client_timeout(hostbuf, port, SOCK_STREAM, 10);
    if (fd < 0) {
        snprintf(buffer, buffer_size, "unable to connect to %s:%d", host, port);
        return;
    }

    D("client: connected on remote on fd %d\n", fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);

    ret = register_socket_transport(fd, serial, port, 0);
    if (ret < 0) {
        adb_close(fd);
        snprintf(buffer, buffer_size, "already connected to %s", serial);
    } else {
        snprintf(buffer, buffer_size, "connected to %s", serial);
    }
}

void connect_emulator(char* port_spec, char* buffer, int buffer_size)
{
    char* port_separator = strchr(port_spec, ',');
    if (!port_separator) {
        snprintf(buffer, buffer_size,
                "unable to parse '%s' as <console port>,<adb port>",
                port_spec);
        return;
    }

    // Zero-terminate console port and make port_separator point to 2nd port.
    *port_separator++ = 0;
    int console_port = strtol(port_spec, NULL, 0);
    int adb_port = strtol(port_separator, NULL, 0);
    if (!(console_port > 0 && adb_port > 0)) {
        *(port_separator - 1) = ',';
        snprintf(buffer, buffer_size,
                "Invalid port numbers: Expected positive numbers, got '%s'",
                port_spec);
        return;
    }

    /* Check if the emulator is already known.
     * Note: There's a small but harmless race condition here: An emulator not
     * present just yet could be registered by another invocation right
     * after doing this check here. However, local_connect protects
     * against double-registration too. From here, a better error message
     * can be produced. In the case of the race condition, the very specific
     * error message won't be shown, but the data doesn't get corrupted. */
    atransport* known_emulator = find_emulator_transport_by_adb_port(adb_port);
    if (known_emulator != NULL) {
        snprintf(buffer, buffer_size,
                "Emulator on port %d already registered.", adb_port);
        return;
    }

    /* Check if more emulators can be registered. Similar unproblematic
     * race condition as above. */
    int candidate_slot = get_available_local_transport_index();
    if (candidate_slot < 0) {
        snprintf(buffer, buffer_size, "Cannot accept more emulators.");
        return;
    }

    /* Preconditions met, try to connect to the emulator. */
    if (!local_connect_arbitrary_ports(console_port, adb_port)) {
        snprintf(buffer, buffer_size,
                "Connected to emulator on ports %d,%d", console_port, adb_port);
    } else {
        snprintf(buffer, buffer_size,
                "Could not connect to emulator on ports %d,%d",
                console_port, adb_port);
    }
}

static void connect_service(int fd, void* cookie)
{
    char buf[4096];
    char resp[4096];
    char *host = cookie;

    if (!strncmp(host, "emu:", 4)) {
        connect_emulator(host + 4, buf, sizeof(buf));
    } else {
        connect_device(host, buf, sizeof(buf));
    }

    // Send response for emulator and device
    snprintf(resp, sizeof(resp), "%04x%s",(unsigned)strlen(buf), buf);
    writex(fd, resp, strlen(resp));
    adb_close(fd);
}
#endif

#if ADB_HOST
asocket*  host_service_to_socket(const char*  name, const char *serial)
{
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker();
    } else if (!strncmp(name, "wait-for-", strlen("wait-for-"))) {
        struct state_info* sinfo = malloc(sizeof(struct state_info));

        if (serial)
            sinfo->serial = strdup(serial);
        else
            sinfo->serial = NULL;

        name += strlen("wait-for-");

        if (!strncmp(name, "local", strlen("local"))) {
            sinfo->transport = kTransportLocal;
            sinfo->state = CS_DEVICE;
        } else if (!strncmp(name, "usb", strlen("usb"))) {
            sinfo->transport = kTransportUsb;
            sinfo->state = CS_DEVICE;
        } else if (!strncmp(name, "any", strlen("any"))) {
            sinfo->transport = kTransportAny;
            sinfo->state = CS_DEVICE;
        } else {
            free(sinfo);
            return NULL;
        }

        int fd = create_service_thread(wait_for_state, sinfo);
        return create_local_socket(fd);
    } else if (!strncmp(name, "connect:", 8)) {
        const char *host = name + 8;
        int fd = create_service_thread(connect_service, (void *)host);
        return create_local_socket(fd);
    }
    return NULL;
}
#endif /* ADB_HOST */
