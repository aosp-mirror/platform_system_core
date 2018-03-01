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

#define TRACE_TAG ADB

#include "sysdeps.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <thread>

#include <android-base/errors.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>

#include "adb.h"
#include "adb_auth.h"
#include "adb_listeners.h"
#include "adb_utils.h"
#include "commandline.h"
#include "sysdeps/chrono.h"
#include "transport.h"

static void setup_daemon_logging() {
    const std::string log_file_path(GetLogFilePath());
    int fd = unix_open(log_file_path.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0640);
    if (fd == -1) {
        fatal("cannot open '%s': %s", log_file_path.c_str(), strerror(errno));
    }
    if (dup2(fd, STDOUT_FILENO) == -1) {
        fatal("cannot redirect stdout: %s", strerror(errno));
    }
    if (dup2(fd, STDERR_FILENO) == -1) {
        fatal("cannot redirect stderr: %s", strerror(errno));
    }
    unix_close(fd);

    fprintf(stderr, "--- adb starting (pid %d) ---\n", getpid());
    LOG(INFO) << adb_version();
}

#if defined(_WIN32)
static BOOL WINAPI ctrlc_handler(DWORD type) {
    // TODO: Consider trying to kill a starting up adb server (if we're in
    // launch_server) by calling GenerateConsoleCtrlEvent().
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}
#endif

void adb_server_cleanup() {
    // Upon exit, we want to clean up in the following order:
    //   1. close_smartsockets, so that we don't get any new clients
    //   2. kick_all_transports, to avoid writing only part of a packet to a transport.
    //   3. usb_cleanup, to tear down the USB stack.
    close_smartsockets();
    kick_all_transports();
    usb_cleanup();
}

static void intentionally_leak() {
    void* p = ::operator new(1);
    // The analyzer is upset about this leaking. NOLINTNEXTLINE
    LOG(INFO) << "leaking pointer " << p;
}

int adb_server_main(int is_daemon, const std::string& socket_spec, int ack_reply_fd) {
#if defined(_WIN32)
    // adb start-server starts us up with stdout and stderr hooked up to
    // anonymous pipes. When the C Runtime sees this, it makes stderr and
    // stdout buffered, but to improve the chance that error output is seen,
    // unbuffer stdout and stderr just like if we were run at the console.
    // This also keeps stderr unbuffered when it is redirected to adb.log.
    if (is_daemon) {
        if (setvbuf(stdout, NULL, _IONBF, 0) == -1) {
            fatal("cannot make stdout unbuffered: %s", strerror(errno));
        }
        if (setvbuf(stderr, NULL, _IONBF, 0) == -1) {
            fatal("cannot make stderr unbuffered: %s", strerror(errno));
        }
    }

    SetConsoleCtrlHandler(ctrlc_handler, TRUE);
#else
    signal(SIGINT, [](int) {
        fdevent_run_on_main_thread([]() { exit(0); });
    });
#endif

    char* leak = getenv("ADB_LEAK");
    if (leak && strcmp(leak, "1") == 0) {
        intentionally_leak();
    }

    if (is_daemon) {
        close_stdin();
        setup_daemon_logging();
    }

    atexit(adb_server_cleanup);

    init_transport_registration();
    init_mdns_transport_discovery();

    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);

    std::string error;

    auto start = std::chrono::steady_clock::now();

    // If we told a previous adb server to quit because of version mismatch, we can get to this
    // point before it's finished exiting. Retry for a while to give it some time.
    while (install_listener(socket_spec, "*smartsocket*", nullptr, 0, nullptr, &error) !=
           INSTALL_STATUS_OK) {
        if (std::chrono::steady_clock::now() - start > 0.5s) {
            fatal("could not install *smartsocket* listener: %s", error.c_str());
        }

        std::this_thread::sleep_for(100ms);
    }

    adb_auth_init();

    if (is_daemon) {
#if !defined(_WIN32)
        // Start a new session for the daemon. Do this here instead of after the fork so
        // that a ctrl-c between the "starting server" and "done starting server" messages
        // gets a chance to terminate the server.
        // setsid will fail with EPERM if it's already been a lead process of new session.
        // Ignore such error.
        if (setsid() == -1 && errno != EPERM) {
            fatal("setsid() failed: %s", strerror(errno));
        }
#endif

        // Wait for the USB scan to complete before notifying the parent that we're up.
        // We need to perform this in a thread, because we would otherwise block the event loop.
        std::thread notify_thread([ack_reply_fd]() {
            adb_wait_for_device_initialization();

            // Any error output written to stderr now goes to adb.log. We could
            // keep around a copy of the stderr fd and use that to write any errors
            // encountered by the following code, but that is probably overkill.
#if defined(_WIN32)
            const HANDLE ack_reply_handle = cast_int_to_handle(ack_reply_fd);
            const CHAR ack[] = "OK\n";
            const DWORD bytes_to_write = arraysize(ack) - 1;
            DWORD written = 0;
            if (!WriteFile(ack_reply_handle, ack, bytes_to_write, &written, NULL)) {
                fatal("adb: cannot write ACK to handle 0x%p: %s", ack_reply_handle,
                      android::base::SystemErrorCodeToString(GetLastError()).c_str());
            }
            if (written != bytes_to_write) {
                fatal("adb: cannot write %lu bytes of ACK: only wrote %lu bytes", bytes_to_write,
                      written);
            }
            CloseHandle(ack_reply_handle);
#else
            // TODO(danalbert): Can't use SendOkay because we're sending "OK\n", not
            // "OKAY".
            if (!android::base::WriteStringToFd("OK\n", ack_reply_fd)) {
                fatal_errno("error writing ACK to fd %d", ack_reply_fd);
            }
            unix_close(ack_reply_fd);
#endif
        });
        notify_thread.detach();
    }

    D("Event loop starting");
    fdevent_loop();

    return 0;
}

int main(int argc, char** argv) {
    adb_trace_init(argv);
    return adb_commandline(argc - 1, const_cast<const char**>(argv + 1));
}
