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

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "sysdeps.h"

#define  TRACE_TAG  TRACE_ADB
#include "adb.h"
#include "file_sync_service.h"

#if ADB_HOST
#  ifndef HAVE_WINSOCK
#    include <netinet/in.h>
#    include <netdb.h>
#  endif
#else
#include <sys/poll.h>
#include <sys/reboot.h>
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

#if ADB_HOST
ADB_MUTEX_DEFINE( dns_lock );

static void dns_service(int fd, void *cookie)
{
    char *hostname = cookie;
    struct hostent *hp;
    unsigned zero = 0;

    adb_mutex_lock(&dns_lock);
    hp = gethostbyname(hostname);
    if(hp == 0) {
        writex(fd, &zero, 4);
    } else {
        writex(fd, hp->h_addr, 4);
    }
    adb_mutex_unlock(&dns_lock);
    adb_close(fd);
}
#else
extern int recovery_mode;

static void recover_service(int s, void *cookie)
{
    unsigned char buf[4096];
    unsigned count = (unsigned) cookie;
    int fd;

    fd = adb_creat("/tmp/update", 0644);
    if(fd < 0) {
        adb_close(s);
        return;
    }

    while(count > 0) {
        unsigned xfer = (count > 4096) ? 4096 : count;
        if(readx(s, buf, xfer)) break;
        if(writex(fd, buf, xfer)) break;
        count -= xfer;
    }

    if(count == 0) {
        writex(s, "OKAY", 4);
    } else {
        writex(s, "FAIL", 4);
    }
    adb_close(fd);
    adb_close(s);

    fd = adb_creat("/tmp/update.begin", 0644);
    adb_close(fd);
}

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

        // quit, and init will restart us as root
        sleep(1);
        exit(1);
    }
}

void restart_tcp_service(int fd, void *cookie)
{
    char buf[100];
    char value[PROPERTY_VALUE_MAX];
    int port = (int)cookie;

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

    // quit, and init will restart us in TCP mode
    sleep(1);
    exit(1);
}

void restart_usb_service(int fd, void *cookie)
{
    char buf[100];

    property_set("service.adb.tcp.port", "0");
    snprintf(buf, sizeof(buf), "restarting in USB mode\n");
    writex(fd, buf, strlen(buf));
    adb_close(fd);

    // quit, and init will restart us in USB mode
    sleep(1);
    exit(1);
}

void reboot_service(int fd, void *arg)
{
    char buf[100];
    int ret;

    sync();
    ret = __reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                    LINUX_REBOOT_CMD_RESTART2, (char *)arg);
    if (ret < 0) {
        snprintf(buf, sizeof(buf), "reboot failed: %s\n", strerror(errno));
        writex(fd, buf, strlen(buf));
    }
    adb_close(fd);
}

void bugreport_service(int fd, void *cookie)
{
    char    buffer[MAX_PAYLOAD];
    int i, s;

    /* start the dumpstate service */
    property_set("ctl.start", "dumpstate");

    /* socket will not be available until service starts */
    for (i = 0; i < 10; i++) {
        s = socket_local_client("dumpstate",
                             ANDROID_SOCKET_NAMESPACE_RESERVED,
                             SOCK_STREAM);
        if (s >= 0)
            break;
        /* try again in 1 second */
        sleep(1);
    }

    if (s < 0) {
        const char* failed = "Failed to connect to dumpstate service\n";
        writex(fd, failed, strlen(failed));
        adb_close(fd);
        return;
    }

    while (1) {
        int length = adb_read(s, buffer, sizeof(buffer));
        if (length <= 0)
            break;
        if (adb_write(fd, buffer, length) <= 0)
            break;
    }
    adb_close(s);
    adb_close(fd);
}

#endif

#if 0
static void echo_service(int fd, void *cookie)
{
    char buf[4096];
    int r;
    char *p;
    int c;

    for(;;) {
        r = read(fd, buf, 4096);
        if(r == 0) goto done;
        if(r < 0) {
            if(errno == EINTR) continue;
            else goto done;
        }

        c = r;
        p = buf;
        while(c > 0) {
            r = write(fd, p, c);
            if(r > 0) {
                c -= r;
                p += r;
                continue;
            }
            if((r < 0) && (errno == EINTR)) continue;
            goto done;
        }
    }
done:
    close(fd);
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
static int create_subprocess(const char *cmd, const char *arg0, const char *arg1)
{
    char *devname;
    int ptm;
    pid_t pid;

    ptm = unix_open("/dev/ptmx", O_RDWR); // | O_NOCTTY);
    if(ptm < 0){
        printf("[ cannot open /dev/ptmx - %s ]\n",strerror(errno));
        return -1;
    }
    fcntl(ptm, F_SETFD, FD_CLOEXEC);

    if(grantpt(ptm) || unlockpt(ptm) ||
       ((devname = (char*) ptsname(ptm)) == 0)){
        printf("[ trouble with /dev/ptmx - %s ]\n", strerror(errno));
        return -1;
    }

    pid = fork();
    if(pid < 0) {
        printf("- fork failed: %s -\n", strerror(errno));
        return -1;
    }

    if(pid == 0){
        int pts;

        setsid();

        pts = unix_open(devname, O_RDWR);
        if(pts < 0) exit(-1);

        dup2(pts, 0);
        dup2(pts, 1);
        dup2(pts, 2);

        adb_close(ptm);

        execl(cmd, cmd, arg0, arg1, NULL);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        // set child's OOM adjustment to zero
        char text[64];
        snprintf(text, sizeof text, "/proc/%d/oom_adj", pid);
        int fd = adb_open(text, O_WRONLY);
        if (fd >= 0) {
            adb_write(fd, "0", 1);
            adb_close(fd);
        } else {
           D("adb: unable to open %s\n", text);
        }

        return ptm;
    }
}
#endif /* !ADB_HOST */

#if ADB_HOST
#define SHELL_COMMAND "/bin/sh"
#else
#define SHELL_COMMAND "/system/bin/sh"
#endif

#if !ADB_HOST
static void shell_service(int s, void *command)
{
    char    buffer[MAX_PAYLOAD];
    char    buffer2[MAX_PAYLOAD];
    struct pollfd ufds[2];
    int     fd, ret = 0;
    unsigned count = 0;
    char** args = (char **)command;
    fd = create_subprocess(SHELL_COMMAND, args[0], args[1]);

    while (1) {
        while (count < sizeof(buffer)) {
            ufds[0].fd = fd;
            ufds[0].events = POLLIN | POLLHUP;
            ufds[0].revents = 0;
            ufds[1].fd = s;
            ufds[1].events = POLLIN | POLLHUP;
            ufds[1].revents = 0;
            // use a 100ms timeout so we don't block indefinitely with our
            // buffer partially filled.
            ret = poll(ufds, 2, 100);
            if (ret <= 0) {
                D("poll returned %d\n", ret);
                // file has closed or we timed out
                // set ret to 1 so we don't exit the outer loop
                ret = 1;
                break;
            }

            if (ufds[0].revents & POLLIN) {
                ret = adb_read(fd, buffer + count, sizeof(buffer) - count);
                D("read fd ret: %d, count: %d\n", ret, count);
                if (ret > 0)
                    count += ret;
                else
                    break;
            }
            if (ufds[1].revents & POLLIN) {
                ret = adb_read(s, buffer2, sizeof(buffer2));
                D("read s ret: %d\n", ret);
                if (ret > 0)
                    adb_write(fd, buffer2, ret);
                else
                    break;
            }

            if ((ufds[0].revents & POLLHUP) || (ufds[1].revents & POLLHUP)) {
                // set flag to exit after flushing the buffer
                ret = -1;
                break;
            }
        }

        D("writing: %d\n", count);
        if (count > 0) {
            adb_write(s, buffer, count);
            count = 0;
        }
        if (ret <= 0)
            break;
    }

    D("shell_service done\n");

    adb_close(fd);
    adb_close(s);
}
#endif // !ADB_HOST

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
            adb_mutex_lock(&dns_lock);
            ret = socket_network_client(name + 1, port, SOCK_STREAM);
            adb_mutex_unlock(&dns_lock);
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
#if ADB_HOST
    } else if(!strncmp("dns:", name, 4)){
        char *n = strdup(name + 4);
        if(n == 0) return -1;
        ret = create_service_thread(dns_service, n);
#else /* !ADB_HOST */
    } else if(!strncmp("dev:", name, 4)) {
        ret = unix_open(name + 4, O_RDWR);
    } else if(!strncmp(name, "framebuffer:", 12)) {
        ret = create_service_thread(framebuffer_service, 0);
    } else if(recovery_mode && !strncmp(name, "recover:", 8)) {
        ret = create_service_thread(recover_service, (void*) atoi(name + 8));
    } else if (!strncmp(name, "jdwp:", 5)) {
        ret = create_jdwp_connection_fd(atoi(name+5));
    } else if (!strncmp(name, "log:", 4)) {
        ret = create_service_thread(log_service, get_log_file_path(name + 4));
    } else if(!HOST && !strncmp(name, "shell:", 6)) {
        const char* args[2];
        if(name[6]) {
            args[0] = "-c";
            args[1] = name + 6;
        } else {
            args[0] = "-";
            args[1] = 0;
        }
        ret = create_service_thread(shell_service, (void *)args);
    } else if(!strncmp(name, "sync:", 5)) {
        ret = create_service_thread(file_sync_service, NULL);
    } else if(!strncmp(name, "remount:", 8)) {
        ret = create_service_thread(remount_service, NULL);
    } else if(!strncmp(name, "reboot:", 7)) {
        const char* arg = name + 7;
        if (*name == 0)
            arg = NULL;
        ret = create_service_thread(reboot_service, (void *)arg);
    } else if(!strncmp(name, "root:", 5)) {
        ret = create_service_thread(restart_root_service, NULL);
    } else if(!strncmp(name, "tcpip:", 6)) {
        int port;
        if (sscanf(name + 6, "%d", &port) == 0) {
            port = 0;
        }
        ret = create_service_thread(restart_tcp_service, (void *)port);
    } else if(!strncmp(name, "usb:", 4)) {
        ret = create_service_thread(restart_usb_service, NULL);
    } else if(!strncmp(name, "bugreport:", 10)) {
        ret = create_service_thread(bugreport_service, NULL);
#endif
#if 0
    } else if(!strncmp(name, "echo:", 5)){
        ret = create_service_thread(echo_service, 0);
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
    }
    return NULL;
}
#endif /* ADB_HOST */
