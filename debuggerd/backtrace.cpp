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

#include <backtrace/Backtrace.h>
#include <UniquePtr.h>

#include "backtrace.h"

#include "utility.h"

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
  _LOG(log, logtype::BACKTRACE, "\n\n----- pid %d at %s -----\n", pid, timestr);

  if (procname) {
    _LOG(log, logtype::BACKTRACE, "Cmd line: %s\n", procname);
  }
  _LOG(log, logtype::BACKTRACE, "ABI: '%s'\n", ABI_STRING);
}

static void dump_process_footer(log_t* log, pid_t pid) {
  _LOG(log, logtype::BACKTRACE, "\n----- end %d -----\n", pid);
}

static void dump_thread(
    log_t* log, pid_t tid, bool attached, bool* detach_failed, int* total_sleep_time_usec) {
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

  _LOG(log, logtype::BACKTRACE, "\n\"%s\" sysTid=%d\n", threadname ? threadname : "<unknown>", tid);

  if (!attached && ptrace(PTRACE_ATTACH, tid, 0, 0) < 0) {
    _LOG(log, logtype::BACKTRACE, "Could not attach to thread: %s\n", strerror(errno));
    return;
  }

  if (!attached && wait_for_sigstop(tid, total_sleep_time_usec, detach_failed) == -1) {
    return;
  }

  UniquePtr<Backtrace> backtrace(Backtrace::Create(tid, BACKTRACE_CURRENT_THREAD));
  if (backtrace->Unwind(0)) {
    dump_backtrace_to_log(backtrace.get(), log, "  ");
  }

  if (!attached && ptrace(PTRACE_DETACH, tid, 0, 0) != 0) {
    _LOG(log, logtype::ERROR, "ptrace detach from %d failed: %s\n", tid, strerror(errno));
    *detach_failed = true;
  }
}

void dump_backtrace(int fd, int amfd, pid_t pid, pid_t tid, bool* detach_failed,
                    int* total_sleep_time_usec) {
  log_t log;
  log.tfd = fd;
  log.amfd = amfd;

  dump_process_header(&log, pid);
  dump_thread(&log, tid, true, detach_failed, total_sleep_time_usec);

  char task_path[64];
  snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);
  DIR* d = opendir(task_path);
  if (d != NULL) {
    struct dirent* de = NULL;
    while ((de = readdir(d)) != NULL) {
      if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
        continue;
      }

      char* end;
      pid_t new_tid = strtoul(de->d_name, &end, 10);
      if (*end || new_tid == tid) {
        continue;
      }

      dump_thread(&log, new_tid, false, detach_failed, total_sleep_time_usec);
    }
    closedir(d);
  }

  dump_process_footer(&log, pid);
}

void dump_backtrace_to_log(Backtrace* backtrace, log_t* log, const char* prefix) {
  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    _LOG(log, logtype::BACKTRACE, "%s%s\n", prefix, backtrace->FormatFrameData(i).c_str());
  }
}
