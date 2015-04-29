/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "bootchart.h"
#include "keywords.h"
#include "log.h"
#include "property_service.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <base/file.h>

#define LOG_ROOT        "/data/bootchart"
#define LOG_STAT        LOG_ROOT"/proc_stat.log"
#define LOG_PROCS       LOG_ROOT"/proc_ps.log"
#define LOG_DISK        LOG_ROOT"/proc_diskstats.log"
#define LOG_HEADER      LOG_ROOT"/header"
#define LOG_ACCT        LOG_ROOT"/kernel_pacct"

#define LOG_STARTFILE   LOG_ROOT"/start"
#define LOG_STOPFILE    LOG_ROOT"/stop"

// Polling period in ms.
static const int BOOTCHART_POLLING_MS = 200;

// Max polling time in seconds.
static const int BOOTCHART_MAX_TIME_SEC = 10*60;

static long long g_last_bootchart_time;
static int g_remaining_samples;

static FILE* log_stat;
static FILE* log_procs;
static FILE* log_disks;

static long long get_uptime_jiffies() {
    std::string uptime;
    if (!android::base::ReadFileToString("/proc/uptime", &uptime)) {
        return 0;
    }
    return 100LL * strtod(uptime.c_str(), NULL);
}

static void log_header() {
    char date[32];
    time_t now_t = time(NULL);
    struct tm now = *localtime(&now_t);
    strftime(date, sizeof(date), "%F %T", &now);

    utsname uts;
    if (uname(&uts) == -1) {
        return;
    }

    char fingerprint[PROP_VALUE_MAX];
    if (property_get("ro.build.fingerprint", fingerprint) == -1) {
        return;
    }

    std::string kernel_cmdline;
    android::base::ReadFileToString("/proc/cmdline", &kernel_cmdline);

    FILE* out = fopen(LOG_HEADER, "we");
    if (out == NULL) {
        return;
    }
    fprintf(out, "version = Android init 0.8 " __TIME__  "\n");
    fprintf(out, "title = Boot chart for Android (%s)\n", date);
    fprintf(out, "system.uname = %s %s %s %s\n", uts.sysname, uts.release, uts.version, uts.machine);
    fprintf(out, "system.release = %s\n", fingerprint);
    // TODO: use /proc/cpuinfo "model name" line for x86, "Processor" line for arm.
    fprintf(out, "system.cpu = %s\n", uts.machine);
    fprintf(out, "system.kernel.options = %s\n", kernel_cmdline.c_str());
    fclose(out);
}

static void do_log_uptime(FILE* log) {
    fprintf(log, "%lld\n", get_uptime_jiffies());
}

static void do_log_file(FILE* log, const char* procfile) {
    do_log_uptime(log);

    std::string content;
    if (android::base::ReadFileToString(procfile, &content)) {
        fprintf(log, "%s\n", content.c_str());
    }
}

static void do_log_procs(FILE* log) {
    do_log_uptime(log);

    std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir("/proc"), closedir);
    struct dirent* entry;
    while ((entry = readdir(dir.get())) != NULL) {
        // Only match numeric values.
        char* end;
        int pid = strtol(entry->d_name, &end, 10);
        if (end != NULL && end > entry->d_name && *end == 0) {
            char filename[32];

            // /proc/<pid>/stat only has truncated task names, so get the full
            // name from /proc/<pid>/cmdline.
            snprintf(filename, sizeof(filename), "/proc/%d/cmdline", pid);
            std::string cmdline;
            android::base::ReadFileToString(filename, &cmdline);
            const char* full_name = cmdline.c_str(); // So we stop at the first NUL.

            // Read process stat line.
            snprintf(filename, sizeof(filename), "/proc/%d/stat", pid);
            std::string stat;
            if (android::base::ReadFileToString(filename, &stat)) {
                if (!cmdline.empty()) {
                    // Substitute the process name with its real name.
                    size_t open = stat.find('(');
                    size_t close = stat.find_last_of(')');
                    if (open != std::string::npos && close != std::string::npos) {
                        stat.replace(open + 1, close - open - 1, full_name);
                    }
                }
                fputs(stat.c_str(), log);
            }
        }
    }

    fputc('\n', log);
}

static int bootchart_init() {
    int timeout = 0;

    std::string start;
    android::base::ReadFileToString(LOG_STARTFILE, &start);
    if (!start.empty()) {
        timeout = atoi(start.c_str());
    } else {
        // When running with emulator, androidboot.bootchart=<timeout>
        // might be passed by as kernel parameters to specify the bootchart
        // timeout. this is useful when using -wipe-data since the /data
        // partition is fresh.
        std::string cmdline;
        android::base::ReadFileToString("/proc/cmdline", &cmdline);
#define KERNEL_OPTION  "androidboot.bootchart="
        if (strstr(cmdline.c_str(), KERNEL_OPTION) != NULL) {
            timeout = atoi(cmdline.c_str() + sizeof(KERNEL_OPTION) - 1);
        }
    }
    if (timeout == 0)
        return 0;

    if (timeout > BOOTCHART_MAX_TIME_SEC)
        timeout = BOOTCHART_MAX_TIME_SEC;

    int count = (timeout*1000 + BOOTCHART_POLLING_MS-1)/BOOTCHART_POLLING_MS;

    log_stat = fopen(LOG_STAT, "we");
    if (log_stat == NULL) {
        return -1;
    }
    log_procs = fopen(LOG_PROCS, "we");
    if (log_procs == NULL) {
        fclose(log_stat);
        return -1;
    }
    log_disks = fopen(LOG_DISK, "we");
    if (log_disks == NULL) {
        fclose(log_stat);
        fclose(log_procs);
        return -1;
    }

    // Create kernel process accounting file.
    close(open(LOG_ACCT, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    acct(LOG_ACCT);

    log_header();
    return count;
}

int do_bootchart_init(int nargs, char** args) {
    g_remaining_samples = bootchart_init();
    if (g_remaining_samples < 0) {
        ERROR("Bootcharting init failure: %s\n", strerror(errno));
    } else if (g_remaining_samples > 0) {
        NOTICE("Bootcharting started (will run for %d s).\n",
               (g_remaining_samples * BOOTCHART_POLLING_MS) / 1000);
    } else {
        NOTICE("Not bootcharting.\n");
    }
    return 0;
}

static int bootchart_step() {
    do_log_file(log_stat,   "/proc/stat");
    do_log_file(log_disks,  "/proc/diskstats");
    do_log_procs(log_procs);

    // Stop if /data/bootchart/stop contains 1.
    std::string stop;
    if (android::base::ReadFileToString(LOG_STOPFILE, &stop) && stop == "1") {
        return -1;
    }

    return 0;
}

/* called to get time (in ms) used by bootchart */
static long long bootchart_gettime() {
    return 10LL*get_uptime_jiffies();
}

static void bootchart_finish() {
    unlink(LOG_STOPFILE);
    fclose(log_stat);
    fclose(log_disks);
    fclose(log_procs);
    acct(NULL);
}

void bootchart_sample(int* timeout) {
    // Do we have any more bootcharting to do?
    if (g_remaining_samples <= 0) {
        return;
    }

    long long current_time = bootchart_gettime();
    int elapsed_time = current_time - g_last_bootchart_time;

    if (elapsed_time >= BOOTCHART_POLLING_MS) {
        /* count missed samples */
        while (elapsed_time >= BOOTCHART_POLLING_MS) {
            elapsed_time -= BOOTCHART_POLLING_MS;
            g_remaining_samples--;
        }
        /* count may be negative, take a sample anyway */
        g_last_bootchart_time = current_time;
        if (bootchart_step() < 0 || g_remaining_samples <= 0) {
            bootchart_finish();
            g_remaining_samples = 0;
        }
    }
    if (g_remaining_samples > 0) {
        int remaining_time = BOOTCHART_POLLING_MS - elapsed_time;
        if (*timeout < 0 || *timeout > remaining_time) {
            *timeout = remaining_time;
        }
    }
}
