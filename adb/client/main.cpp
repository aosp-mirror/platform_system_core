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

#define TRACE_TAG TRACE_ADB

#include "sysdeps.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

// We only build the affinity WAR code for Linux.
#if defined(__linux__)
#include <sched.h>
#endif

#include "base/file.h"
#include "base/logging.h"
#include "base/stringprintf.h"

#include "adb.h"
#include "adb_auth.h"
#include "adb_listeners.h"
#include "transport.h"

#if defined(WORKAROUND_BUG6558362) && defined(__linux__)
static const bool kWorkaroundBug6558362 = true;
#else
static const bool kWorkaroundBug6558362 = false;
#endif

static void adb_workaround_affinity(void) {
#if defined(__linux__)
    const char affinity_env[] = "ADB_CPU_AFFINITY_BUG6558362";
    const char* cpunum_str = getenv(affinity_env);
    if (cpunum_str == nullptr || *cpunum_str == '\0') {
        return;
    }

    char* strtol_res;
    int cpu_num = strtol(cpunum_str, &strtol_res, 0);
    if (*strtol_res != '\0') {
        fatal("bad number (%s) in env var %s. Expecting 0..n.\n", cpunum_str,
              affinity_env);
    }

    cpu_set_t cpu_set;
    sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
    D("orig cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);

    CPU_ZERO(&cpu_set);
    CPU_SET(cpu_num, &cpu_set);
    sched_setaffinity(0, sizeof(cpu_set), &cpu_set);

    sched_getaffinity(0, sizeof(cpu_set), &cpu_set);
    D("new cpu_set[0]=0x%08lx\n", cpu_set.__bits[0]);
#else
    // No workaround was ever implemented for the other platforms.
#endif
}

#if defined(_WIN32)
static const char kNullFileName[] = "NUL";

static BOOL WINAPI ctrlc_handler(DWORD type) {
    exit(STATUS_CONTROL_C_EXIT);
    return TRUE;
}

static std::string GetLogFilePath() {
    const char log_name[] = "adb.log";
    char temp_path[MAX_PATH - sizeof(log_name) + 1];

    // https://msdn.microsoft.com/en-us/library/windows/desktop/aa364992%28v=vs.85%29.aspx
    DWORD nchars = GetTempPath(sizeof(temp_path), temp_path);
    CHECK_LE(nchars, sizeof(temp_path));
    if (nchars == 0) {
        // TODO(danalbert): Log the error message from FormatError().
        // Windows unfortunately has two errnos, errno and GetLastError(), so
        // I'm not sure what to do about PLOG here. Probably better to just
        // ignore it and add a simplified version of FormatError() for use in
        // log messages.
        LOG(ERROR) << "Error creating log file";
    }

    return std::string(temp_path) + log_name;
}
#else
static const char kNullFileName[] = "/dev/null";

static std::string GetLogFilePath() {
    return std::string("/tmp/adb.log");
}
#endif

static void close_stdin() {
    int fd = unix_open(kNullFileName, O_RDONLY);
    CHECK_NE(fd, -1);
    dup2(fd, STDIN_FILENO);
    unix_close(fd);
}

static void setup_daemon_logging(void) {
    int fd = unix_open(GetLogFilePath().c_str(), O_WRONLY | O_CREAT | O_APPEND,
                       0640);
    if (fd == -1) {
        fd = unix_open(kNullFileName, O_WRONLY);
    }
    dup2(fd, STDOUT_FILENO);
    dup2(fd, STDERR_FILENO);
    unix_close(fd);

#ifdef _WIN32
    // On Windows, stderr is buffered by default, so switch to non-buffered
    // to match Linux.
    setvbuf(stderr, NULL, _IONBF, 0);
#endif
    fprintf(stderr, "--- adb starting (pid %d) ---\n", getpid());
}

int adb_main(int is_daemon, int server_port) {
    HOST = 1;

#if defined(_WIN32)
    SetConsoleCtrlHandler(ctrlc_handler, TRUE);
#else
    signal(SIGPIPE, SIG_IGN);
#endif

    init_transport_registration();

    if (kWorkaroundBug6558362 && is_daemon) {
        adb_workaround_affinity();
    }

    usb_init();
    local_init(DEFAULT_ADB_LOCAL_TRANSPORT_PORT);
    adb_auth_init();

    std::string local_name = android::base::StringPrintf("tcp:%d", server_port);
    if (install_listener(local_name, "*smartsocket*", nullptr, 0)) {
        LOG(FATAL) << "Could not install *smartsocket* listener";
    }

    if (is_daemon) {
        // Inform our parent that we are up and running.
        // TODO(danalbert): Can't use SendOkay because we're sending "OK\n", not
        // "OKAY".
        // TODO(danalbert): Why do we use stdout for Windows? There is a
        // comment in launch_server() that suggests that non-Windows uses
        // stderr because it is non-buffered. So perhaps the history is that
        // stdout was preferred for all platforms, but it was discovered that
        // non-Windows needed a non-buffered fd, so stderr was used there.
        // Note that using stderr on unix means that if you do
        // `ADB_TRACE=all adb start-server`, it will say "ADB server didn't ACK"
        // and "* failed to start daemon *" because the adb server will write
        // logging to stderr, obscuring the OK\n output that is sent to stderr.
#if defined(_WIN32)
        int reply_fd = STDOUT_FILENO;
        // Change stdout mode to binary so \n => \r\n translation does not
        // occur. In a moment stdout will be reopened to the daemon log file
        // anyway.
        _setmode(reply_fd, _O_BINARY);
#else
        int reply_fd = STDERR_FILENO;
#endif
        android::base::WriteStringToFd("OK\n", reply_fd);
        close_stdin();
        setup_daemon_logging();
    }

    D("Event loop starting\n");
    fdevent_loop();

    return 0;
}

int main(int argc, char** argv) {
    adb_sysdeps_init();
    adb_trace_init(argv);
    D("Handling commandline()\n");
    return adb_commandline(argc - 1, const_cast<const char**>(argv + 1));
}
