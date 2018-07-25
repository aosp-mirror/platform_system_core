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

#include <thread>

#include <android-base/file.h>
#include <android-base/parsenetaddress.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>

#if !ADB_HOST
#include <android-base/properties.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <log/log_properties.h>
#endif

#include "adb.h"
#include "adb_io.h"
#include "adb_utils.h"
#if !ADB_HOST
#include "daemon/framebuffer_service.h"
#include "daemon/set_verity_enable_state_service.h"
#endif
#include "file_sync_service.h"
#include "remount_service.h"
#include "services.h"
#include "shell_service.h"
#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"

namespace {

void service_bootstrap_func(std::string service_name,
                            std::function<void(android::base::unique_fd)> func,
                            android::base::unique_fd fd) {
    adb_thread_setname(android::base::StringPrintf("%s svc %d", service_name.c_str(), fd.get()));
    func(std::move(fd));
}

#if !ADB_HOST

void restart_root_service(android::base::unique_fd fd) {
    if (getuid() == 0) {
        WriteFdExactly(fd.get(), "adbd is already running as root\n");
        return;
    }
    if (!__android_log_is_debuggable()) {
        WriteFdExactly(fd.get(), "adbd cannot run as root in production builds\n");
        return;
    }

    android::base::SetProperty("service.adb.root", "1");
    WriteFdExactly(fd.get(), "restarting adbd as root\n");
}

void restart_unroot_service(android::base::unique_fd fd) {
    if (getuid() != 0) {
        WriteFdExactly(fd.get(), "adbd not running as root\n");
        return;
    }
    android::base::SetProperty("service.adb.root", "0");
    WriteFdExactly(fd.get(), "restarting adbd as non root\n");
}

void restart_tcp_service(android::base::unique_fd fd, int port) {
    if (port <= 0) {
        WriteFdFmt(fd.get(), "invalid port %d\n", port);
        return;
    }

    android::base::SetProperty("service.adb.tcp.port", android::base::StringPrintf("%d", port));
    WriteFdFmt(fd.get(), "restarting in TCP mode port: %d\n", port);
}

void restart_usb_service(android::base::unique_fd fd) {
    android::base::SetProperty("service.adb.tcp.port", "0");
    WriteFdExactly(fd.get(), "restarting in USB mode\n");
}

bool reboot_service_impl(android::base::unique_fd fd, const std::string& arg) {
    std::string reboot_arg = arg;
    bool auto_reboot = false;

    if (reboot_arg == "sideload-auto-reboot") {
        auto_reboot = true;
        reboot_arg = "sideload";
    }

    // It reboots into sideload mode by setting "--sideload" or "--sideload_auto_reboot"
    // in the command file.
    if (reboot_arg == "sideload") {
        if (getuid() != 0) {
            WriteFdExactly(fd, "'adb root' is required for 'adb reboot sideload'.\n");
            return false;
        }

        const std::vector<std::string> options = {
            auto_reboot ? "--sideload_auto_reboot" : "--sideload"
        };
        std::string err;
        if (!write_bootloader_message(options, &err)) {
            D("Failed to set bootloader message: %s", err.c_str());
            return false;
        }

        reboot_arg = "recovery";
    }

    sync();

    if (reboot_arg.empty()) reboot_arg = "adb";
    std::string reboot_string = android::base::StringPrintf("reboot,%s", reboot_arg.c_str());
    if (!android::base::SetProperty(ANDROID_RB_PROPERTY, reboot_string)) {
        WriteFdFmt(fd, "reboot (%s) failed\n", reboot_string.c_str());
        return false;
    }

    return true;
}

void reboot_service(android::base::unique_fd fd, const std::string& arg) {
    if (!reboot_service_impl(std::move(fd), arg)) {
        return;
    }
    // Don't return early. Give the reboot command time to take effect
    // to avoid messing up scripts which do "adb reboot && adb wait-for-device"
    while (true) {
        pause();
    }
}

void reconnect_service(android::base::unique_fd fd, atransport* t) {
    WriteFdExactly(fd, "done");
    kick_transport(t);
}

int reverse_service(const char* command, atransport* transport) {
    int s[2];
    if (adb_socketpair(s)) {
        PLOG(ERROR) << "cannot create service socket pair.";
        return -1;
    }
    VLOG(SERVICES) << "service socketpair: " << s[0] << ", " << s[1];
    if (handle_forward_request(command, transport, s[1]) < 0) {
        SendFail(s[1], "not a reverse forwarding command");
    }
    adb_close(s[1]);
    return s[0];
}

// Shell service string can look like:
//   shell[,arg1,arg2,...]:[command]
int ShellService(const std::string& args, const atransport* transport) {
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

android::base::unique_fd create_service_thread(const char* service_name,
                                               std::function<void(android::base::unique_fd)> func) {
    int s[2];
    if (adb_socketpair(s)) {
        printf("cannot create service socket pair\n");
        return android::base::unique_fd();
    }
    D("socketpair: (%d,%d)", s[0], s[1]);

#if !ADB_HOST
    if (strcmp(service_name, "sync") == 0) {
        // Set file sync service socket to maximum size
        int max_buf = LINUX_MAX_SOCKET_SIZE;
        adb_setsockopt(s[0], SOL_SOCKET, SO_SNDBUF, &max_buf, sizeof(max_buf));
        adb_setsockopt(s[1], SOL_SOCKET, SO_SNDBUF, &max_buf, sizeof(max_buf));
    }
#endif // !ADB_HOST

    std::thread(service_bootstrap_func, service_name, func, android::base::unique_fd(s[1])).detach();

    D("service thread started, %d:%d",s[0], s[1]);
    return android::base::unique_fd(s[0]);
}

}  // namespace

int service_to_fd(const char* name, atransport* transport) {
    int ret = -1;

    if (is_socket_spec(name)) {
        std::string error;
        ret = socket_spec_connect(name, &error);
        if (ret < 0) {
            LOG(ERROR) << "failed to connect to socket '" << name << "': " << error;
        }
#if !ADB_HOST
    } else if(!strncmp("dev:", name, 4)) {
        ret = unix_open(name + 4, O_RDWR | O_CLOEXEC);
    } else if (!strncmp(name, "framebuffer:", 12)) {
        ret = create_service_thread("fb", framebuffer_service).release();
    } else if (!strncmp(name, "jdwp:", 5)) {
        ret = create_jdwp_connection_fd(atoi(name + 5));
    } else if (!strncmp(name, "shell", 5)) {
        ret = ShellService(name + 5, transport);
    } else if (!strncmp(name, "exec:", 5)) {
        ret = StartSubprocess(name + 5, nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if (!strncmp(name, "sync:", 5)) {
        ret = create_service_thread("sync", file_sync_service).release();
    } else if (!strncmp(name, "remount:", 8)) {
        std::string options(name + strlen("remount:"));
        ret = create_service_thread("remount",
                                    std::bind(remount_service, std::placeholders::_1, options))
                      .release();
    } else if (!strncmp(name, "reboot:", 7)) {
        std::string arg(name + strlen("reboot:"));
        ret = create_service_thread("reboot", std::bind(reboot_service, std::placeholders::_1, arg))
                      .release();
    } else if (!strncmp(name, "root:", 5)) {
        ret = create_service_thread("root", restart_root_service).release();
    } else if (!strncmp(name, "unroot:", 7)) {
        ret = create_service_thread("unroot", restart_unroot_service).release();
    } else if (!strncmp(name, "backup:", 7)) {
        ret = StartSubprocess(
                android::base::StringPrintf("/system/bin/bu backup %s", (name + 7)).c_str(),
                nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if (!strncmp(name, "restore:", 8)) {
        ret = StartSubprocess("/system/bin/bu restore", nullptr, SubprocessType::kRaw,
                              SubprocessProtocol::kNone);
    } else if (!strncmp(name, "tcpip:", 6)) {
        int port;
        if (sscanf(name + 6, "%d", &port) != 1) {
            return -1;
        }
        ret = create_service_thread("tcp",
                                    std::bind(restart_tcp_service, std::placeholders::_1, port))
                      .release();
    } else if (!strncmp(name, "usb:", 4)) {
        ret = create_service_thread("usb", restart_usb_service).release();
    } else if (!strncmp(name, "reverse:", 8)) {
        ret = reverse_service(name + 8, transport);
    } else if (!strncmp(name, "disable-verity:", 15)) {
        ret = create_service_thread("verity-on", std::bind(set_verity_enabled_state_service,
                                                           std::placeholders::_1, false))
                      .release();
    } else if (!strncmp(name, "enable-verity:", 15)) {
        ret = create_service_thread("verity-off", std::bind(set_verity_enabled_state_service,
                                                            std::placeholders::_1, true))
                      .release();
    } else if (!strcmp(name, "reconnect")) {
        ret = create_service_thread("reconnect",
                                    std::bind(reconnect_service, std::placeholders::_1, transport))
                      .release();
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
    TransportId transport_id;
    ConnectionState state;
};

static void wait_for_state(int fd, void* data) {
    std::unique_ptr<state_info> sinfo(reinterpret_cast<state_info*>(data));

    D("wait_for_state %d", sinfo->state);

    while (true) {
        bool is_ambiguous = false;
        std::string error = "unknown error";
        const char* serial = sinfo->serial.length() ? sinfo->serial.c_str() : nullptr;
        atransport* t = acquire_one_transport(sinfo->transport_type, serial, sinfo->transport_id,
                                              &is_ambiguous, &error);
        if (t != nullptr && (sinfo->state == kCsAny || sinfo->state == t->GetConnectionState())) {
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

void connect_emulator(const std::string& port_spec, std::string* response) {
    std::vector<std::string> pieces = android::base::Split(port_spec, ",");
    if (pieces.size() != 2) {
        *response = android::base::StringPrintf("unable to parse '%s' as <console port>,<adb port>",
                                                port_spec.c_str());
        return;
    }

    int console_port = strtol(pieces[0].c_str(), nullptr, 0);
    int adb_port = strtol(pieces[1].c_str(), nullptr, 0);
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

static void connect_service(android::base::unique_fd fd, std::string host) {
    std::string response;
    if (!strncmp(host.c_str(), "emu:", 4)) {
        connect_emulator(host.c_str() + 4, &response);
    } else {
        connect_device(host.c_str(), &response);
    }

    // Send response for emulator and device
    SendProtocolString(fd.get(), response);
}
#endif

#if ADB_HOST
asocket* host_service_to_socket(const char* name, const char* serial, TransportId transport_id) {
    if (!strcmp(name,"track-devices")) {
        return create_device_tracker(false);
    } else if (!strcmp(name, "track-devices-l")) {
        return create_device_tracker(true);
    } else if (android::base::StartsWith(name, "wait-for-")) {
        name += strlen("wait-for-");

        std::unique_ptr<state_info> sinfo = std::make_unique<state_info>();
        if (sinfo == nullptr) {
            fprintf(stderr, "couldn't allocate state_info: %s", strerror(errno));
            return nullptr;
        }

        if (serial) sinfo->serial = serial;
        sinfo->transport_id = transport_id;

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

        int fd = create_service_thread(
                         "wait", std::bind(wait_for_state, std::placeholders::_1, sinfo.get()))
                         .release();
        if (fd != -1) {
            sinfo.release();
        }
        return create_local_socket(fd);
    } else if (!strncmp(name, "connect:", 8)) {
        std::string host(name + strlen("connect:"));
        int fd = create_service_thread("connect",
                                       std::bind(connect_service, std::placeholders::_1, host))
                         .release();
        return create_local_socket(fd);
    }
    return nullptr;
}
#endif /* ADB_HOST */
