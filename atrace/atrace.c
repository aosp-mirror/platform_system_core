/*
 * Copyright (C) 2012 The Android Open Source Project
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <time.h>

/* Command line options */
static int g_traceDurationSeconds = 5;
static bool g_traceSchedSwitch = false;
static bool g_traceWorkqueue = false;
static bool g_traceOverwrite = false;

/* Global state */
static bool g_traceAborted = false;

/* Sys file paths */
static const char* k_traceClockPath =
    "/sys/kernel/debug/tracing/trace_clock";

static const char* k_tracingOverwriteEnablePath =
    "/sys/kernel/debug/tracing/options/overwrite";

static const char* k_schedSwitchEnablePath =
    "/sys/kernel/debug/tracing/events/sched/sched_switch/enable";

static const char* k_workqueueEnablePath =
    "/sys/kernel/debug/tracing/events/workqueue/enable";

static const char* k_tracingOnPath =
    "/sys/kernel/debug/tracing/tracing_on";

static const char* k_tracePath =
    "/sys/kernel/debug/tracing/trace";

static const char* k_traceMarkerPath =
    "/sys/kernel/debug/tracing/trace_marker";

// Write a string to a file, returning true if the write was successful.
bool writeStr(const char* filename, const char* str)
{
    int fd = open(filename, O_WRONLY);
    if (fd == -1) {
        fprintf(stderr, "error opening %s: %s (%d)\n", filename,
                strerror(errno), errno);
        return false;
    }

    bool ok = true;
    ssize_t len = strlen(str);
    if (write(fd, str, len) != len) {
        fprintf(stderr, "error writing to %s: %s (%d)\n", filename,
                strerror(errno), errno);
        ok = false;
    }

    close(fd);

    return ok;
}

// Enable or disable a kernel option by writing a "1" or a "0" into a /sys file.
static bool setKernelOptionEnable(const char* filename, bool enable)
{
    return writeStr(filename, enable ? "1" : "0");
}

// Enable or disable overwriting of the kernel trace buffers.  Disabling this
// will cause tracing to stop once the trace buffers have filled up.
static bool setTraceOverwriteEnable(bool enable)
{
    return setKernelOptionEnable(k_tracingOverwriteEnablePath, enable);
}

// Enable or disable tracing of the kernel scheduler switching.
static bool setSchedSwitchTracingEnable(bool enable)
{
    return setKernelOptionEnable(k_schedSwitchEnablePath, enable);
}

// Enable or disable tracing of the kernel workqueues.
static bool setWorkqueueTracingEnabled(bool enable)
{
    return setKernelOptionEnable(k_workqueueEnablePath, enable);
}

// Enable or disable kernel tracing.
static bool setTracingEnabled(bool enable)
{
    return setKernelOptionEnable(k_tracingOnPath, enable);
}

// Clear the contents of the kernel trace.
static bool clearTrace()
{
    int traceFD = creat(k_tracePath, 0);
    if (traceFD == -1) {
        fprintf(stderr, "error truncating %s: %s (%d)\n", k_tracePath,
                strerror(errno), errno);
        return false;
    }

    close(traceFD);

    return true;
}

// Enable or disable the kernel's use of the global clock.  Disabling the global
// clock will result in the kernel using a per-CPU local clock.
static bool setGlobalClockEnable(bool enable)
{
    return writeStr(k_traceClockPath, enable ? "global" : "local");
}

// Enable tracing in the kernel.
static bool startTrace()
{
    bool ok = true;

    // Set up the tracing options.
    ok &= setTraceOverwriteEnable(g_traceOverwrite);
    ok &= setSchedSwitchTracingEnable(g_traceSchedSwitch);
    ok &= setWorkqueueTracingEnabled(g_traceWorkqueue);
    ok &= setGlobalClockEnable(true);

    // Enable tracing.
    ok &= setTracingEnabled(true);

    if (!ok) {
        fprintf(stderr, "error: unable to start trace\n");
    }

    return ok;
}

// Disable tracing in the kernel.
static void stopTrace()
{
    // Disable tracing.
    setTracingEnabled(false);

    // Set the options back to their defaults.
    setTraceOverwriteEnable(true);
    setSchedSwitchTracingEnable(false);
    setWorkqueueTracingEnabled(false);
    setGlobalClockEnable(false);
}

// Read the current kernel trace and write it to stdout.
static void dumpTrace()
{
    int traceFD = open(k_tracePath, O_RDWR);
    if (traceFD == -1) {
        fprintf(stderr, "error opening %s: %s (%d)\n", k_tracePath,
                strerror(errno), errno);
        return;
    }

    ssize_t sent = 0;
    while ((sent = sendfile(STDOUT_FILENO, traceFD, NULL, 64*1024*1024)) > 0);
    if (sent == -1) {
        fprintf(stderr, "error dumping trace: %s (%d)\n", strerror(errno),
                errno);
    }

    close(traceFD);
}

// Print the command usage help to stderr.
static void showHelp(const char *cmd)
{
    fprintf(stderr, "usage: %s [options]\n", cmd);
    fprintf(stderr, "options include:\n"
                    "  -c              trace into a circular buffer\n"
                    "  -s              trace the kernel scheduler switches\n"
                    "  -t N            trace for N seconds [defualt 5]\n"
                    "  -w              trace the kernel workqueue\n");
}

static void handleSignal(int signo) {
    g_traceAborted = true;
}

static void registerSigHandler() {
    struct sigaction sa;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sa.sa_handler = handleSignal;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int main(int argc, char **argv)
{
    if (argc == 2 && 0 == strcmp(argv[1], "--help")) {
        showHelp(argv[0]);
        exit(0);
    }

    if (getuid() != 0) {
        fprintf(stderr, "error: %s must be run as root.", argv[0]);
    }

    for (;;) {
        int ret;

        ret = getopt(argc, argv, "cst:w");

        if (ret < 0) {
            break;
        }

        switch(ret) {
            case 'c':
                g_traceOverwrite = true;
            break;

            case 's':
                g_traceSchedSwitch = true;
            break;

            case 't':
                g_traceDurationSeconds = atoi(optarg);
            break;

            case 'w':
                g_traceWorkqueue = true;
            break;

            default:
                showHelp(argv[0]);
                exit(-1);
            break;
        }
    }

    registerSigHandler();

    bool ok = startTrace();

    if (ok) {
        printf("capturing trace...");
        fflush(stdout);

        // We clear the trace after starting it because tracing gets enabled for
        // each CPU individually in the kernel. Having the beginning of the trace
        // contain entries from only one CPU can cause "begin" entries without a
        // matching "end" entry to show up if a task gets migrated from one CPU to
        // another.
        ok = clearTrace();

        if (ok) {
            // Sleep to allow the trace to be captured.
            struct timespec timeLeft;
            timeLeft.tv_sec = g_traceDurationSeconds;
            timeLeft.tv_nsec = 0;
            do {
                if (g_traceAborted) {
                    break;
                }
            } while (nanosleep(&timeLeft, &timeLeft) == -1 && errno == EINTR);
        }
    }

    // Stop the trace and restore the default settings.
    stopTrace();

    if (ok) {
        if (!g_traceAborted) {
            printf(" done\nTRACE:\n");
            fflush(stdout);
            dumpTrace();
        } else {
            printf("\ntrace aborted.\n");
            fflush(stdout);
        }
        clearTrace();
    } else {
        fprintf(stderr, "unable to start tracing\n");
    }

    return g_traceAborted ? 1 : 0;
}
