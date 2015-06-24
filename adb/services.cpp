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

#define TRACE_TAG TRACE_SERVICES

#include "sysdeps.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if !ADB_HOST
#include <pty.h>
#include <termios.h>
#endif

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include <base/file.h>
#include <base/stringprintf.h>
#include <base/strings.h>

#if !ADB_HOST
#include "cutils/android_reboot.h"
#include "cutils/properties.h"
#endif

#include "adb.h"
#include "adb_io.h"
#include "file_sync_service.h"
#include "remount_service.h"
#include "transport.h"

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};


void *service_bootstrap_func(void *x)
{
    stinfo* sti = reinterpret_cast<stinfo*>(x);
    sti->func(sti->fd, sti->cookie);
    free(sti);
    return 0;
}

#if !ADB_HOST

void restart_root_service(int fd, void *cookie) {
    if (getuid() == 0) {
        WriteFdExactly(fd, "adbd is already running as root\n");
        adb_close(fd);
    } else {
        char value[PROPERTY_VALUE_MAX];
        property_get("ro.debuggable", value, "");
        if (strcmp(value, "1") != 0) {
            WriteFdExactly(fd, "adbd cannot run as root in production builds\n");
            adb_close(fd);
            return;
        }

        property_set("service.adb.root", "1");
        WriteFdExactly(fd, "restarting adbd as root\n");
        adb_close(fd);
    }
}

void restart_unroot_service(int fd, void *cookie) {
    if (getuid() != 0) {
        WriteFdExactly(fd, "adbd not running as root\n");
        adb_close(fd);
    } else {
        property_set("service.adb.root", "0");
        WriteFdExactly(fd, "restarting adbd as non root\n");
        adb_close(fd);
    }
}

void restart_tcp_service(int fd, void *cookie) {
    int port = (int) (uintptr_t) cookie;
    if (port <= 0) {
        WriteFdFmt(fd, "invalid port %d\n", port);
        adb_close(fd);
        return;
    }

    char value[PROPERTY_VALUE_MAX];
    snprintf(value, sizeof(value), "%d", port);
    property_set("service.adb.tcp.port", value);
    WriteFdFmt(fd, "restarting in TCP mode port: %d\n", port);
    adb_close(fd);
}

void restart_usb_service(int fd, void *cookie) {
    property_set("service.adb.tcp.port", "0");
    WriteFdExactly(fd, "restarting in USB mode\n");
    adb_close(fd);
}

static bool reboot_service_impl(int fd, const char* arg) {
    const char* reboot_arg = arg;
    bool auto_reboot = false;

    if (strcmp(reboot_arg, "sideload-auto-reboot") == 0) {
        auto_reboot = true;
        reboot_arg = "sideload";
    }

    // It reboots into sideload mode by setting "--sideload" or "--sideload_auto_reboot"
    // in the command file.
    if (strcmp(reboot_arg, "sideload") == 0) {
        if (getuid() != 0) {
            WriteFdExactly(fd, "'adb root' is required for 'adb reboot sideload'.\n");
            return false;
        }

        const char* const recovery_dir = "/cache/recovery";
        const char* const command_file = "/cache/recovery/command";
        // Ensure /cache/recovery exists.
        if (adb_mkdir(recovery_dir, 0770) == -1 && errno != EEXIST) {
            D("Failed to create directory '%s': %s\n", recovery_dir, strerror(errno));
            return false;
        }

        bool write_status = android::base::WriteStringToFile(
                auto_reboot ? "--sideload_auto_reboot" : "--sideload", command_file);
        if (!write_status) {
            return false;
        }

        reboot_arg = "recovery";
    }

    sync();

    char property_val[PROPERTY_VALUE_MAX];
    int ret = snprintf(property_val, sizeof(property_val), "reboot,%s", reboot_arg);
    if (ret >= static_cast<int>(sizeof(property_val))) {
        WriteFdFmt(fd, "reboot string too long: %d\n", ret);
        return false;
    }

    ret = property_set(ANDROID_RB_PROPERTY, property_val);
    if (ret < 0) {
        WriteFdFmt(fd, "reboot failed: %d\n", ret);
        return false;
    }

    return true;
}

void reboot_service(int fd, void* arg)
{
    if (reboot_service_impl(fd, static_cast<const char*>(arg))) {
        // Don't return early. Give the reboot command time to take effect
        // to avoid messing up scripts which do "adb reboot && adb wait-for-device"
        while (true) {
            pause();
        }
    }

    free(arg);
    adb_close(fd);
}

void reverse_service(int fd, void* arg)
{
    const char* command = reinterpret_cast<const char*>(arg);

    if (handle_forward_request(command, kTransportAny, NULL, fd) < 0) {
        SendFail(fd, "not a reverse forwarding command");
    }
    free(arg);
    adb_close(fd);
}

#endif

static int create_service_thread(void (*func)(int, void *), void *cookie)
{
    int s[2];
    if (adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return -1;
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

    stinfo* sti = reinterpret_cast<stinfo*>(malloc(sizeof(stinfo)));
    if (sti == nullptr) {
        fatal("cannot allocate stinfo");
    }
    sti->func = func;
    sti->cookie = cookie;
    sti->fd = s[1];

    if (!adb_thread_create(service_bootstrap_func, sti)) {
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

#if !ADB_HOST
static int create_subproc_pty(const char* cmd, const char* arg0,
                              const char* arg1, pid_t* pid) {
    D("create_subproc_pty(cmd=%s, arg0=%s, arg1=%s)\n", cmd, arg0, arg1);
    char pts_name[PATH_MAX];
    int ptm;
    *pid = forkpty(&ptm, pts_name, nullptr, nullptr);
    if (*pid == -1) {
        printf("- fork failed: %s -\n", strerror(errno));
        unix_close(ptm);
        return -1;
    }

    if (*pid == 0) {
        init_subproc_child();

        int pts = unix_open(pts_name, O_RDWR | O_CLOEXEC);
        if (pts == -1) {
            fprintf(stderr, "child failed to open pseudo-term slave %s: %s\n",
                    pts_name, strerror(errno));
            unix_close(ptm);
            exit(-1);
        }

        // arg0 is "-c" in batch mode and "-" in interactive mode.
        if (strcmp(arg0, "-c") == 0) {
            termios tattr;
            if (tcgetattr(pts, &tattr) == -1) {
                fprintf(stderr, "tcgetattr failed: %s\n", strerror(errno));
                unix_close(pts);
                unix_close(ptm);
                exit(-1);
            }

            cfmakeraw(&tattr);
            if (tcsetattr(pts, TCSADRAIN, &tattr) == -1) {
                fprintf(stderr, "tcsetattr failed: %s\n", strerror(errno));
                unix_close(pts);
                unix_close(ptm);
                exit(-1);
            }
        }

        dup2(pts, STDIN_FILENO);
        dup2(pts, STDOUT_FILENO);
        dup2(pts, STDERR_FILENO);

        unix_close(pts);
        unix_close(ptm);

        execl(cmd, cmd, arg0, arg1, nullptr);
        fprintf(stderr, "- exec '%s' failed: %s (%d) -\n",
                cmd, strerror(errno), errno);
        exit(-1);
    } else {
        return ptm;
    }
}
#endif // !ADB_HOST

static int create_subproc_raw(const char *cmd, const char *arg0, const char *arg1, pid_t *pid)
{
    D("create_subproc_raw(cmd=%s, arg0=%s, arg1=%s)\n", cmd, arg0, arg1);
#if defined(_WIN32)
    fprintf(stderr, "error: create_subproc_raw not implemented on Win32 (%s %s %s)\n", cmd, arg0, arg1);
    return -1;
#else

    // 0 is parent socket, 1 is child socket
    int sv[2];
    if (adb_socketpair(sv) < 0) {
        printf("[ cannot create socket pair - %s ]\n", strerror(errno));
        return -1;
    }
    D("socketpair: (%d,%d)", sv[0], sv[1]);

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
#endif /* !defined(_WIN32) */
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
    while (true) {
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
      res = WriteFdExactly(SHELL_EXIT_NOTIFY_FD, &fd, sizeof(fd)) ? 0 : -1;
      D("notified shell exit via fd=%d for pid=%d res=%d errno=%d\n",
        SHELL_EXIT_NOTIFY_FD, pid, res, errno);
    }
}

static int create_subproc_thread(const char *name, bool pty = false) {
    const char *arg0, *arg1;
    if (name == 0 || *name == 0) {
        arg0 = "-"; arg1 = 0;
    } else {
        arg0 = "-c"; arg1 = name;
    }

    pid_t pid = -1;
    int ret_fd;
    if (pty) {
        ret_fd = create_subproc_pty(SHELL_COMMAND, arg0, arg1, &pid);
    } else {
        ret_fd = create_subproc_raw(SHELL_COMMAND, arg0, arg1, &pid);
    }
    D("create_subproc ret_fd=%d pid=%d\n", ret_fd, pid);

    stinfo* sti = reinterpret_cast<stinfo*>(malloc(sizeof(stinfo)));
    if(sti == 0) fatal("cannot allocate stinfo");
    sti->func = subproc_waiter_service;
    sti->cookie = (void*) (uintptr_t) pid;
    sti->fd = ret_fd;

    if (!adb_thread_create(service_bootstrap_func, sti)) {
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
        ret = create_subproc_thread(name + 6, true);
    } else if(!HOST && !strncmp(name, "exec:", 5)) {
        ret = create_subproc_thread(name + 5);
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
    } else if(!strncmp(name, "unroot:", 7)) {
        ret = create_service_thread(restart_unroot_service, NULL);
    } else if(!strncmp(name, "backup:", 7)) {
        ret = create_subproc_thread(android::base::StringPrintf("/system/bin/bu backup %s",
                                                                (name + 7)).c_str());
    } else if(!strncmp(name, "restore:", 8)) {
        ret = create_subproc_thread("/system/bin/bu restore");
    } else if(!strncmp(name, "tcpip:", 6)) {
        int port;
        if (sscanf(name + 6, "%d", &port) != 1) {
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
        ret = create_service_thread(set_verity_enabled_state_service, (void*)0);
    } else if(!strncmp(name, "enable-verity:", 15)) {
        ret = create_service_thread(set_verity_enabled_state_service, (void*)1);
#endif
    }
    if (ret >= 0) {
        close_on_exec(ret);
    }
    return ret;
}

#if ADB_HOST
struct state_info {
    TransportType transport_type;
    char* serial;
    ConnectionState state;
};

static void wait_for_state(int fd, void* cookie)
{
    state_info* sinfo = reinterpret_cast<state_info*>(cookie);

    D("wait_for_state %d\n", sinfo->state);

    std::string error_msg = "unknown error";
    atransport* t = acquire_one_transport(sinfo->state, sinfo->transport_type, sinfo->serial,
                                          &error_msg);
    if (t != nullptr) {
        SendOkay(fd);
    } else {
        SendFail(fd, error_msg);
    }

    if (sinfo->serial)
        free(sinfo->serial);
    free(sinfo);
    adb_close(fd);
    D("wait_for_state is done\n");
}

static void connect_device(const std::string& host, std::string* response) {
    if (host.empty()) {
        *response = "empty host name";
        return;
    }

    std::vector<std::string> pieces = android::base::Split(host, ":");
    const std::string& hostname = pieces[0];

    int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    if (pieces.size() > 1) {
        if (sscanf(pieces[1].c_str(), "%d", &port) != 1) {
            *response = android::base::StringPrintf("bad port number %s", pieces[1].c_str());
            return;
        }
    }

    // This may look like we're putting 'host' back together,
    // but we're actually inserting the default port if necessary.
    std::string serial = android::base::StringPrintf("%s:%d", hostname.c_str(), port);

    int fd = socket_network_client_timeout(hostname.c_str(), port, SOCK_STREAM, 10);
    if (fd < 0) {
        *response = android::base::StringPrintf("unable to connect to %s:%d",
                                                hostname.c_str(), port);
        return;
    }

    D("client: connected on remote on fd %d\n", fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);

    int ret = register_socket_transport(fd, serial.c_str(), port, 0);
    if (ret < 0) {
        adb_close(fd);
        *response = android::base::StringPrintf("already connected to %s", serial.c_str());
    } else {
        *response = android::base::StringPrintf("connected to %s", serial.c_str());
    }
}

void connect_emulator(const std::string& port_spec, std::string* response) {
    std::vector<std::string> pieces = android::base::Split(port_spec, ",");
    if (pieces.size() != 2) {
        *response = android::base::StringPrintf("unable to parse '%s' as <console port>,<adb port>",
                                                port_spec.c_str());
        return;
    }

    int console_port = strtol(pieces[0].c_str(), NULL, 0);
    int adb_port = strtol(pieces[1].c_str(), NULL, 0);
    if (console_port <= 0 || adb_port <= 0) {
        *response = android::base::StringPrintf("Invalid port numbers: %s", port_spec.c_str());
        return;
    }

    // Check if the emulator is already known.
    // Note: There's a small but harmless race condition here: An emulator not
    // present just yet could be registered by another invocation right
    // after doing this check here. However, local_connect protects
    // against double-registration too. From here, a better error message
    // can be produced. In the case of the race condition, the very specific
    // error message won't be shown, but the data doesn't get corrupted.
    atransport* known_emulator = find_emulator_transport_by_adb_port(adb_port);
    if (known_emulator != nullptr) {
        *response = android::base::StringPrintf("Emulator already registered on port %d", adb_port);
        return;
    }

    // Check if more emulators can be registered. Similar unproblematic
    // race condition as above.
    int candidate_slot = get_available_local_transport_index();
    if (candidate_slot < 0) {
        *response = "Cannot accept more emulators";
        return;
    }

    // Preconditions met, try to connect to the emulator.
    if (!local_connect_arbitrary_ports(console_port, adb_port)) {
        *response = android::base::StringPrintf("Connected to emulator on ports %d,%d",
                                                console_port, adb_port);
    } else {
        *response = android::base::StringPrintf("Could not connect to emulator on ports %d,%d",
                                                console_port, adb_port);
    }
}

static void connect_service(int fd, void* data) {
    char* host = reinterpret_cast<char*>(data);
    std::string response;
    if (!strncmp(host, "emu:", 4)) {
        connect_emulator(host + 4, &response);
    } else {
        connect_device(host, &response);
    }
    free(host);

    // Send response for emulator and device
    SendProtocolString(fd, response);
    adb_close(fd);
}
#endif

#if ADB_HOST
asocket*  host_service_to_socket(const char*  name, const char *serial)
{
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker();
    } else if (!strncmp(name, "wait-for-", strlen("wait-for-"))) {
        auto sinfo = reinterpret_cast<state_info*>(malloc(sizeof(state_info)));
        if (sinfo == nullptr) {
            fprintf(stderr, "couldn't allocate state_info: %s", strerror(errno));
            return NULL;
        }

        if (serial)
            sinfo->serial = strdup(serial);
        else
            sinfo->serial = NULL;

        name += strlen("wait-for-");

        if (!strncmp(name, "local", strlen("local"))) {
            sinfo->transport_type = kTransportLocal;
            sinfo->state = kCsDevice;
        } else if (!strncmp(name, "usb", strlen("usb"))) {
            sinfo->transport_type = kTransportUsb;
            sinfo->state = kCsDevice;
        } else if (!strncmp(name, "any", strlen("any"))) {
            sinfo->transport_type = kTransportAny;
            sinfo->state = kCsDevice;
        } else {
            if (sinfo->serial) {
                free(sinfo->serial);
            }
            free(sinfo);
            return NULL;
        }

        int fd = create_service_thread(wait_for_state, sinfo);
        return create_local_socket(fd);
    } else if (!strncmp(name, "connect:", 8)) {
        char* host = strdup(name + 8);
        int fd = create_service_thread(connect_service, host);
        return create_local_socket(fd);
    }
    return NULL;
}
#endif /* ADB_HOST */
