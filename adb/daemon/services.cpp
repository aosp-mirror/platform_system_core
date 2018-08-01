/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <netdb.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <thread>

#include <android-base/file.h>
#include <android-base/parsenetaddress.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <bootloader_message/bootloader_message.h>
#include <cutils/android_reboot.h>
#include <cutils/sockets.h>
#include <log/log_properties.h>

#include "adb.h"
#include "adb_io.h"
#include "adb_unique_fd.h"
#include "adb_utils.h"
#include "services.h"
#include "socket_spec.h"
#include "sysdeps.h"
#include "transport.h"

#include "daemon/file_sync_service.h"
#include "daemon/framebuffer_service.h"
#include "daemon/remount_service.h"
#include "daemon/set_verity_enable_state_service.h"
#include "daemon/shell_service.h"

void restart_root_service(unique_fd fd) {
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

void restart_unroot_service(unique_fd fd) {
    if (getuid() != 0) {
        WriteFdExactly(fd.get(), "adbd not running as root\n");
        return;
    }
    android::base::SetProperty("service.adb.root", "0");
    WriteFdExactly(fd.get(), "restarting adbd as non root\n");
}

void restart_tcp_service(unique_fd fd, int port) {
    if (port <= 0) {
        WriteFdFmt(fd.get(), "invalid port %d\n", port);
        return;
    }

    android::base::SetProperty("service.adb.tcp.port", android::base::StringPrintf("%d", port));
    WriteFdFmt(fd.get(), "restarting in TCP mode port: %d\n", port);
}

void restart_usb_service(unique_fd fd) {
    android::base::SetProperty("service.adb.tcp.port", "0");
    WriteFdExactly(fd.get(), "restarting in USB mode\n");
}

bool reboot_service_impl(unique_fd fd, const std::string& arg) {
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
            WriteFdExactly(fd.get(), "'adb root' is required for 'adb reboot sideload'.\n");
            return false;
        }

        const std::vector<std::string> options = {auto_reboot ? "--sideload_auto_reboot"
                                                              : "--sideload"};
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
        WriteFdFmt(fd.get(), "reboot (%s) failed\n", reboot_string.c_str());
        return false;
    }

    return true;
}

void reboot_service(unique_fd fd, const std::string& arg) {
    if (!reboot_service_impl(std::move(fd), arg)) {
        return;
    }
    // Don't return early. Give the reboot command time to take effect
    // to avoid messing up scripts which do "adb reboot && adb wait-for-device"
    while (true) {
        pause();
    }
}

void reconnect_service(unique_fd fd, atransport* t) {
    WriteFdExactly(fd.get(), "done");
    kick_transport(t);
}

unique_fd reverse_service(const char* command, atransport* transport) {
    int s[2];
    if (adb_socketpair(s)) {
        PLOG(ERROR) << "cannot create service socket pair.";
        return unique_fd{};
    }
    VLOG(SERVICES) << "service socketpair: " << s[0] << ", " << s[1];
    if (!handle_forward_request(command, transport, s[1])) {
        SendFail(s[1], "not a reverse forwarding command");
    }
    adb_close(s[1]);
    return unique_fd{s[0]};
}

// Shell service string can look like:
//   shell[,arg1,arg2,...]:[command]
unique_fd ShellService(const std::string& args, const atransport* transport) {
    size_t delimiter_index = args.find(':');
    if (delimiter_index == std::string::npos) {
        LOG(ERROR) << "No ':' found in shell service arguments: " << args;
        return unique_fd{};
    }

    const std::string service_args = args.substr(0, delimiter_index);
    const std::string command = args.substr(delimiter_index + 1);

    // Defaults:
    //   PTY for interactive, raw for non-interactive.
    //   No protocol.
    //   $TERM set to "dumb".
    SubprocessType type(command.empty() ? SubprocessType::kPty : SubprocessType::kRaw);
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

unique_fd daemon_service_to_fd(const char* name, atransport* transport) {
    if (!strncmp("dev:", name, 4)) {
        return unique_fd{unix_open(name + 4, O_RDWR | O_CLOEXEC)};
    } else if (!strncmp(name, "framebuffer:", 12)) {
        return create_service_thread("fb", framebuffer_service);
    } else if (!strncmp(name, "jdwp:", 5)) {
        return create_jdwp_connection_fd(atoi(name + 5));
    } else if (!strncmp(name, "shell", 5)) {
        return ShellService(name + 5, transport);
    } else if (!strncmp(name, "exec:", 5)) {
        return StartSubprocess(name + 5, nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if (!strncmp(name, "sync:", 5)) {
        return create_service_thread("sync", file_sync_service);
    } else if (!strncmp(name, "remount:", 8)) {
        std::string options(name + strlen("remount:"));
        return create_service_thread("remount",
                                     std::bind(remount_service, std::placeholders::_1, options));
    } else if (!strncmp(name, "reboot:", 7)) {
        std::string arg(name + strlen("reboot:"));
        return create_service_thread("reboot",
                                     std::bind(reboot_service, std::placeholders::_1, arg));
    } else if (!strncmp(name, "root:", 5)) {
        return create_service_thread("root", restart_root_service);
    } else if (!strncmp(name, "unroot:", 7)) {
        return create_service_thread("unroot", restart_unroot_service);
    } else if (!strncmp(name, "backup:", 7)) {
        return StartSubprocess(
                android::base::StringPrintf("/system/bin/bu backup %s", (name + 7)).c_str(),
                nullptr, SubprocessType::kRaw, SubprocessProtocol::kNone);
    } else if (!strncmp(name, "restore:", 8)) {
        return StartSubprocess("/system/bin/bu restore", nullptr, SubprocessType::kRaw,
                               SubprocessProtocol::kNone);
    } else if (!strncmp(name, "tcpip:", 6)) {
        int port;
        if (sscanf(name + 6, "%d", &port) != 1) {
            return unique_fd{};
        }
        return create_service_thread("tcp",
                                     std::bind(restart_tcp_service, std::placeholders::_1, port));
    } else if (!strncmp(name, "usb:", 4)) {
        return create_service_thread("usb", restart_usb_service);
    } else if (!strncmp(name, "reverse:", 8)) {
        return reverse_service(name + 8, transport);
    } else if (!strncmp(name, "disable-verity:", 15)) {
        return create_service_thread("verity-on", std::bind(set_verity_enabled_state_service,
                                                            std::placeholders::_1, false));
    } else if (!strncmp(name, "enable-verity:", 15)) {
        return create_service_thread("verity-off", std::bind(set_verity_enabled_state_service,
                                                             std::placeholders::_1, true));
    } else if (!strcmp(name, "reconnect")) {
        return create_service_thread(
                "reconnect", std::bind(reconnect_service, std::placeholders::_1, transport));
    }
    return unique_fd{};
}
