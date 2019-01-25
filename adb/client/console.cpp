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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>

#include "adb.h"
#include "adb_client.h"
#include "adb_io.h"
#include "adb_utils.h"

// Return the console authentication command for the emulator, if needed
static std::string adb_construct_auth_command() {
    static const char auth_token_filename[] = ".emulator_console_auth_token";

    std::string auth_token_path = adb_get_homedir_path();
    auth_token_path += OS_PATH_SEPARATOR;
    auth_token_path += auth_token_filename;

    // read the token
    std::string token;
    if (!android::base::ReadFileToString(auth_token_path, &token)
        || token.empty()) {
        // we either can't read the file, or it doesn't exist, or it's empty -
        // either way we won't add any authentication command.
        return {};
    }

    // now construct and return the actual command: "auth <token>\n"
    std::string command = "auth ";
    command += token;
    command += '\n';
    return command;
}

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

    std::string error;
    int fd = network_loopback_client(port, SOCK_STREAM, &error);
    if (fd == -1) {
        fprintf(stderr, "error: could not connect to TCP port %d: %s\n", port,
                error.c_str());
        return -1;
    }
    return fd;
}

int adb_send_emulator_command(int argc, const char** argv, const char* serial) {
    unique_fd fd(connect_to_console(serial));
    if (fd == -1) {
        return 1;
    }

    std::string commands = adb_construct_auth_command();

    for (int i = 1; i < argc; i++) {
        commands.append(argv[i]);
        commands.push_back(i == argc - 1 ? '\n' : ' ');
    }

    commands.append("quit\n");

    if (!WriteFdExactly(fd, commands)) {
        fprintf(stderr, "error: cannot write to emulator: %s\n",
                strerror(errno));
        return 1;
    }

    // Drain output that the emulator console has sent us to prevent a problem
    // on Windows where if adb closes the socket without reading all the data,
    // the emulator's next call to recv() will have an ECONNABORTED error,
    // preventing the emulator from reading the command that adb has sent.
    // https://code.google.com/p/android/issues/detail?id=21021
    int result;
    std::string emulator_output;
    do {
        char buf[BUFSIZ];
        result = adb_read(fd, buf, sizeof(buf));
        // Keep reading until zero bytes (orderly/graceful shutdown) or an
        // error. If 'adb emu kill' is executed, the emulator calls exit() with
        // the socket open (and shutdown(SD_SEND) was not called), which causes
        // Windows to send a TCP RST segment which causes adb to get ECONNRESET.
        // Any other emu command is followed by the quit command that we
        // appended above, and that causes the emulator to close the socket
        // which should cause zero bytes (orderly/graceful shutdown) to be
        // returned.
        if (result > 0) emulator_output.append(buf, result);
    } while (result > 0);

    // Note: the following messages are expected to be quite stable from emulator.
    //
    // Emulator console will send the following message upon connection:
    //
    // Android Console: Authentication required
    // Android Console: type 'auth <auth_token>' to authenticate
    // Android Console: you can find your <auth_token> in
    // '/<path-to-home>/.emulator_console_auth_token'
    // OK\r\n
    //
    // and the following after authentication:
    // Android Console: type 'help' for a list of commands
    // OK\r\n
    //
    // So try search and skip first two "OK\r\n", print the rest.
    //
    const std::string delims = "OK\r\n";
    size_t found = 0;
    for (int i = 0; i < 2; ++i) {
        const size_t result = emulator_output.find(delims, found);
        if (result == std::string::npos) {
            break;
        } else {
            found = result + delims.size();
        }
    }

    printf("%s", emulator_output.c_str() + found);
    return 0;
}
