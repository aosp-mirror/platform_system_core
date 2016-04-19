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

#define TRACE_TAG SERVICES

#include "sysdeps.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef _WIN32
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include <android-base/file.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#if !ADB_HOST
#include "cutils/android_reboot.h"
#include "cutils/properties.h"
#endif

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#include "file_sync_service.h"
#include "remount_service.h"
#include "services.h"
#include "shell_service.h"
#include "sysdeps.h"
#include "transport.h"

struct stinfo {
    void (*func)(int fd, void *cookie);
    int fd;
    void *cookie;
};

static void service_bootstrap_func(void* x) {
    stinfo* sti = reinterpret_cast<stinfo*>(x);
    adb_thread_setname(android::base::StringPrintf("service %d", sti->fd));
    sti->func(sti->fd, sti->cookie);
    free(sti);
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
            D("Failed to create directory '%s': %s", recovery_dir, strerror(errno));
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

static void reconnect_service(int fd, void* arg) {
    WriteFdExactly(fd, "done");
    adb_close(fd);
    atransport* t = static_cast<atransport*>(arg);
    kick_transport(t);
}

int reverse_service(const char* command) {
    int s[2];
    if (adb_socketpair(s)) {
        PLOG(ERROR) << "cannot create service socket pair.";
        return -1;
    }
    VLOG(SERVICES) << "service socketpair: " << s[0] << ", " << s[1];
    if (handle_forward_request(command, kTransportAny, nullptr, s[1]) < 0) {
        SendFail(s[1], "not a reverse forwarding command");
    }
    adb_close(s[1]);
    return s[0];
}

// Shell service string can look like:
//   shell[,arg1,arg2,...]:[command]
static int ShellService(const std::string& args, const atransport* transport) {
    size_t delimiter_index = args.find(':');
    if (delimiter_index == std::string::npos) {
        LOG(ERROR) << "No ':' found in shell service arguments: " << args;
        return -1;
    }

    const std::string service_args = args.substr(0, delimiter_index);
    const std::string command = args.substr(delimiter_index + 1);

    // Defaults:
    //   PTY for interactive, raw for non-interactive.
    //   No protocol.
    //   $TERM set to "dumb".
    SubprocessType type(command.empty() ? SubprocessType::kPty
                                        : SubprocessType::kRaw);
    SubprocessProtocol protocol = SubprocessProtocol::kNone;
    std::string terminal_type = "dumb";

    for (const std::string& arg : android::base::Split(service_args, ",")) {
        if (arg == kShellServiceArgRaw) {
            type = SubprocessType::kRaw;
        } else if (arg == kShellServiceArgPty) {
            type = SubprocessType::kPty;
        } else if (arg == kShellServiceArgShellProtocol) {
            protocol = SubprocessProtocol::kShell;
        } else if (android::base::StartsWith(arg, "TERM=")) {
            terminal_type = arg.substr(5);
        } else if (!arg.empty()) {
            // This is not an error to allow for future expansion.
            LOG(WARNING) << "Ignoring unknown shell service argument: " << arg;
        }
    }

    return StartSubprocess(command.c_str(), terminal_type.c_str(), type, protocol);
}

#endif  // !ADB_HOST

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

    D("service thread started, %d:%d",s[0], s[1]);
    return s[0];
}

int service_to_fd(const char* name, const atransport* transport) {
    int ret = -1;

    if(!strncmp(name, "tcp:", 4)) {
        int port = atoi(name + 4);
        name = strchr(name + 4, ':');
        if(name == 0) {
            std::string error;
            ret = network_loopback_client(port, SOCK_STREAM, &error);
            if (ret >= 0)
                disable_tcp_nagle(ret);
        } else {
#if ADB_HOST
            std::string error;
            ret = network_connect(name + 1, port, SOCK_STREAM, 0, &error);
#else
            return -1;
#endif
        }
#if !defined(_WIN32)   /* winsock doesn't implement unix domain sockets */
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
    } else if(!strncmp(name, "shell", 5)) {
        ret = ShellService(name + 5, transport);
    } else if(!strncmp(name, "exec:", 5)) {
        ret = StartSubprocess(name + 5, nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
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
        ret = StartSubprocess(android::base::StringPrintf("/system/bin/bu backup %s",
                                                          (name + 7)).c_str(),
                              nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if(!strncmp(name, "restore:", 8)) {
        ret = StartSubprocess("/system/bin/bu restore", nullptr, SubprocessType::kRaw,
                              SubprocessProtocol::kNone);
    } else if(!strncmp(name, "tcpip:", 6)) {
        int port;
        if (sscanf(name + 6, "%d", &port) != 1) {
            return -1;
        }
        ret = create_service_thread(restart_tcp_service, (void *) (uintptr_t) port);
    } else if(!strncmp(name, "usb:", 4)) {
        ret = create_service_thread(restart_usb_service, NULL);
    } else if (!strncmp(name, "reverse:", 8)) {
        ret = reverse_service(name + 8);
    } else if(!strncmp(name, "disable-verity:", 15)) {
        ret = create_service_thread(set_verity_enabled_state_service, (void*)0);
    } else if(!strncmp(name, "enable-verity:", 15)) {
        ret = create_service_thread(set_verity_enabled_state_service, (void*)1);
    } else if (!strcmp(name, "reconnect")) {
        ret = create_service_thread(reconnect_service, const_cast<atransport*>(transport));
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
    std::string serial;
    ConnectionState state;
};

static void wait_for_state(int fd, void* data) {
    std::unique_ptr<state_info> sinfo(reinterpret_cast<state_info*>(data));

    D("wait_for_state %d", sinfo->state);

    while (true) {
        bool is_ambiguous = false;
        std::string error = "unknown error";
        const char* serial = sinfo->serial.length() ? sinfo->serial.c_str() : NULL;
        atransport* t = acquire_one_transport(sinfo->transport_type, serial, &is_ambiguous, &error);
        if (t != nullptr && (sinfo->state == kCsAny || sinfo->state == t->connection_state)) {
            SendOkay(fd);
            break;
        } else if (!is_ambiguous) {
            adb_pollfd pfd = {.fd = fd, .events = POLLIN };
            int rc = adb_poll(&pfd, 1, 1000);
            if (rc < 0) {
                SendFail(fd, error);
                break;
            } else if (rc > 0 && (pfd.revents & POLLHUP) != 0) {
                // The other end of the socket is closed, probably because the other side was
                // terminated, bail out.
                break;
            }

            // Try again...
        } else {
            SendFail(fd, error);
            break;
        }
    }

    adb_close(fd);
    D("wait_for_state is done");
}

static void connect_device(const std::string& address, std::string* response) {
    if (address.empty()) {
        *response = "empty address";
        return;
    }

    std::string serial;
    std::string host;
    int port = DEFAULT_ADB_LOCAL_TRANSPORT_PORT;
    if (!android::base::ParseNetAddress(address, &host, &port, &serial, response)) {
        return;
    }

    std::string error;
    int fd = network_connect(host.c_str(), port, SOCK_STREAM, 10, &error);
    if (fd == -1) {
        *response = android::base::StringPrintf("unable to connect to %s: %s",
                                                serial.c_str(), error.c_str());
        return;
    }

    D("client: connected %s remote on fd %d", serial.c_str(), fd);
    close_on_exec(fd);
    disable_tcp_nagle(fd);

    // Send a TCP keepalive ping to the device every second so we can detect disconnects.
    if (!set_tcp_keepalive(fd, 1)) {
        D("warning: failed to configure TCP keepalives (%s)", strerror(errno));
    }

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
    std::string error;
    if (!local_connect_arbitrary_ports(console_port, adb_port, &error)) {
        *response = android::base::StringPrintf("Connected to emulator on ports %d,%d",
                                                console_port, adb_port);
    } else {
        *response = android::base::StringPrintf("Could not connect to emulator on ports %d,%d: %s",
                                                console_port, adb_port, error.c_str());
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
asocket* host_service_to_socket(const char* name, const char* serial) {
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker();
    } else if (android::base::StartsWith(name, "wait-for-")) {
        name += strlen("wait-for-");

        std::unique_ptr<state_info> sinfo(new state_info);
        if (sinfo == nullptr) {
            fprintf(stderr, "couldn't allocate state_info: %s", strerror(errno));
            return nullptr;
        }

        if (serial) sinfo->serial = serial;

        if (android::base::StartsWith(name, "local")) {
            name += strlen("local");
            sinfo->transport_type = kTransportLocal;
        } else if (android::base::StartsWith(name, "usb")) {
            name += strlen("usb");
            sinfo->transport_type = kTransportUsb;
        } else if (android::base::StartsWith(name, "any")) {
            name += strlen("any");
            sinfo->transport_type = kTransportAny;
        } else {
            return nullptr;
        }

        if (!strcmp(name, "-device")) {
            sinfo->state = kCsDevice;
        } else if (!strcmp(name, "-recovery")) {
            sinfo->state = kCsRecovery;
        } else if (!strcmp(name, "-sideload")) {
            sinfo->state = kCsSideload;
        } else if (!strcmp(name, "-bootloader")) {
            sinfo->state = kCsBootloader;
        } else if (!strcmp(name, "-any")) {
            sinfo->state = kCsAny;
        } else {
            return nullptr;
        }

        int fd = create_service_thread(wait_for_state, sinfo.release());
        return create_local_socket(fd);
    } else if (!strncmp(name, "connect:", 8)) {
        char* host = strdup(name + 8);
        int fd = create_service_thread(connect_service, host);
        return create_local_socket(fd);
    }
    return NULL;
}
#endif /* ADB_HOST */
