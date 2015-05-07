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

#include "sysdeps.h"

#include <stdio.h>

#include "base/file.h"
#include "base/logging.h"
#include "base/strings.h"

#include "adb.h"
#include "adb_client.h"

// Return the console port of the currently connected emulator (if any) or -1 if
// there is no emulator, and -2 if there is more than one.
static int adb_get_emulator_console_port(const char* serial) {
    if (serial) {
        // The user specified a serial number; is it an emulator?
        int port;
        return (sscanf(serial, "emulator-%d", &port) == 1) ? port : -1;
    }

    // No specific device was given, so get the list of connected devices and
    // search for emulators. If there's one, we'll take it. If there are more
    // than one, that's an error.
    std::string devices;
    std::string error;
    if (!adb_query("host:devices", &devices, &error)) {
        fprintf(stderr, "error: no emulator connected: %s\n", error.c_str());
        return -1;
    }

    int port;
    size_t emulator_count = 0;
    for (const auto& device : android::base::Split(devices, "\n")) {
        if (sscanf(device.c_str(), "emulator-%d", &port) == 1) {
            if (++emulator_count > 1) {
                fprintf(
                    stderr, "error: more than one emulator detected; use -s\n");
                return -1;
            }
        }
    }

    if (emulator_count == 0) {
        fprintf(stderr, "error: no emulator detected\n");
        return -1;
    }

    return port;
}

static int connect_to_console(const char* serial) {
    int port = adb_get_emulator_console_port(serial);
    if (port == -1) {
        return -1;
    }

    int fd = socket_loopback_client(port, SOCK_STREAM);
    if (fd == -1) {
        fprintf(stderr, "error: could not connect to TCP port %d\n", port);
        return -1;
    }
    return fd;
}

int adb_send_emulator_command(int argc, const char** argv, const char* serial) {
    int fd = connect_to_console(serial);
    if (fd == -1) {
        return 1;
    }

    for (int i = 1; i < argc; i++) {
        adb_write(fd, argv[i], strlen(argv[i]));
        adb_write(fd, i == argc - 1 ? "\n" : " ", 1);
    }

    const char disconnect_command[] = "quit\n";
    if (adb_write(fd, disconnect_command, sizeof(disconnect_command) - 1) == -1) {
        LOG(FATAL) << "Could not finalize emulator command";
    }

    // Drain output that the emulator console has sent us to prevent a problem
    // on Windows where if adb closes the socket without reading all the data,
    // the emulator's next call to recv() will have an ECONNABORTED error,
    // preventing the emulator from reading the command that adb has sent.
    // https://code.google.com/p/android/issues/detail?id=21021
    int result;
    do {
        char buf[BUFSIZ];
        result = adb_read(fd, buf, sizeof(buf));
        // Keep reading until zero bytes (EOF) or an error. If 'adb emu kill'
        // is executed, the emulator calls exit() which causes adb to get
        // ECONNRESET. Any other emu command is followed by the quit command
        // that we sent above, and that causes the emulator to close the socket
        // which should cause zero bytes (EOF) to be returned.
    } while (result > 0);

    adb_close(fd);

    return 0;
}
