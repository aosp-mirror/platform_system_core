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

#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <limits.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ptrace.h>

#include <corkscrew/backtrace.h>

#include "tombstone.h"
#include "utility.h"

#define STACK_DEPTH 32

static void dump_process_header(log_t* log, pid_t pid) {
    char path[PATH_MAX];
    char procnamebuf[1024];
    char* procname = NULL;
    FILE* fp;

    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    if ((fp = fopen(path, "r"))) {
        procname = fgets(procnamebuf, sizeof(procnamebuf), fp);
        fclose(fp);
    }

    time_t t = time(NULL);
    struct tm tm;
    localtime_r(&t, &tm);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%F %T", &tm);
    _LOG(log, false, "\n\n----- pid %d at %s -----\n", pid, timestr);

    if (procname) {
        _LOG(log, false, "Cmd line: %s\n", procname);
    }
}

static void dump_process_footer(log_t* log, pid_t pid) {
    _LOG(log, false, "\n----- end %d -----\n", pid);
}

static void dump_thread(log_t* log, pid_t tid, ptrace_context_t* context, bool attached,
        bool* detach_failed, int* total_sleep_time_usec) {
    char path[PATH_MAX];
    char threadnamebuf[1024];
    char* threadname = NULL;
    FILE* fp;

    snprintf(path, sizeof(path), "/proc/%d/comm", tid);
    if ((fp = fopen(path, "r"))) {
        threadname = fgets(threadnamebuf, sizeof(threadnamebuf), fp);
        fclose(fp);
        if (threadname) {
            size_t len = strlen(threadname);
            if (len && threadname[len - 1] == '\n') {
                threadname[len - 1] = '\0';
            }
        }
    }

    _LOG(log, false, "\n\"%s\" sysTid=%d\n", threadname ? threadname : "<unknown>", tid);

    if (!attached && ptrace(PTRACE_ATTACH, tid, 0, 0) < 0) {
        _LOG(log, false, "Could not attach to thread: %s\n", strerror(errno));
        return;
    }

    wait_for_stop(tid, total_sleep_time_usec);

    backtrace_frame_t backtrace[STACK_DEPTH];
    ssize_t frames = unwind_backtrace_ptrace(tid, context, backtrace, 0, STACK_DEPTH);
    if (frames <= 0) {
        _LOG(log, false, "Could not obtain stack trace for thread.\n");
    } else {
        backtrace_symbol_t backtrace_symbols[STACK_DEPTH];
        get_backtrace_symbols_ptrace(context, backtrace, frames, backtrace_symbols);
        for (size_t i = 0; i < (size_t)frames; i++) {
            char line[MAX_BACKTRACE_LINE_LENGTH];
            format_backtrace_line(i, &backtrace[i], &backtrace_symbols[i],
                    line, MAX_BACKTRACE_LINE_LENGTH);
            _LOG(log, false, "  %s\n", line);
        }
        free_backtrace_symbols(backtrace_symbols, frames);
    }

    if (!attached && ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
        LOG("ptrace detach from %d failed: %s\n", tid, strerror(errno));
        *detach_failed = true;
    }
}

void dump_backtrace(int fd, pid_t pid, pid_t tid, bool* detach_failed,
        int* total_sleep_time_usec) {
    log_t log;
    log.tfd = fd;
    log.quiet = true;

    ptrace_context_t* context = load_ptrace_context(tid);
    dump_process_header(&log, pid);
    dump_thread(&log, tid, context, true, detach_failed, total_sleep_time_usec);

    char task_path[64];
    snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
    DIR* d = opendir(task_path);
    if (d) {
        struct dirent debuf;
        struct dirent *de;
        while (!readdir_r(d, &debuf, &de) && de) {
            if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
                continue;
            }

            char* end;
            pid_t new_tid = strtoul(de->d_name, &end, 10);
            if (*end || new_tid == tid) {
                continue;
            }

            dump_thread(&log, new_tid, context, false, detach_failed, total_sleep_time_usec);
        }
        closedir(d);
    }

    dump_process_footer(&log, pid);
    free_ptrace_context(context);
}
