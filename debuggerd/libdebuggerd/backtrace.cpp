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

#define LOG_TAG "DEBUG"

#include "libdebuggerd/backtrace.h"

#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <memory>
#include <string>

#include <backtrace/Backtrace.h>
#include <log/log.h>

#include "libdebuggerd/utility.h"

static void dump_process_header(log_t* log, pid_t pid, const char* process_name) {
  time_t t = time(NULL);
  struct tm tm;
  localtime_r(&t, &tm);
  char timestr[64];
  strftime(timestr, sizeof(timestr), "%F %T", &tm);
  _LOG(log, logtype::BACKTRACE, "\n\n----- pid %d at %s -----\n", pid, timestr);

  if (process_name) {
    _LOG(log, logtype::BACKTRACE, "Cmd line: %s\n", process_name);
  }
  _LOG(log, logtype::BACKTRACE, "ABI: '%s'\n", ABI_STRING);
}

static void dump_process_footer(log_t* log, pid_t pid) {
  _LOG(log, logtype::BACKTRACE, "\n----- end %d -----\n", pid);
}

static void log_thread_name(log_t* log, pid_t tid, const char* thread_name) {
  _LOG(log, logtype::BACKTRACE, "\n\"%s\" sysTid=%d\n", thread_name, tid);
}

static void dump_thread(log_t* log, BacktraceMap* map, pid_t pid, pid_t tid,
                        const std::string& thread_name) {
  log_thread_name(log, tid, thread_name.c_str());

  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, tid, map));
  if (backtrace->Unwind(0)) {
    dump_backtrace_to_log(backtrace.get(), log, "  ");
  } else {
    ALOGE("Unwind failed: tid = %d: %s", tid,
          backtrace->GetErrorString(backtrace->GetError()).c_str());
  }
}

void dump_backtrace(int fd, BacktraceMap* map, pid_t pid, pid_t tid, const std::string& process_name,
                    const std::map<pid_t, std::string>& threads, std::string* amfd_data) {
  log_t log;
  log.tfd = fd;
  log.amfd_data = amfd_data;

  dump_process_header(&log, pid, process_name.c_str());
  dump_thread(&log, map, pid, tid, threads.find(tid)->second.c_str());

  for (const auto& it : threads) {
    pid_t thread_tid = it.first;
    const std::string& thread_name = it.second;
    if (thread_tid != tid) {
      dump_thread(&log, map, pid, thread_tid, thread_name.c_str());
    }
  }

  dump_process_footer(&log, pid);
}

void dump_backtrace_ucontext(int output_fd, ucontext_t* ucontext) {
  pid_t pid = getpid();
  pid_t tid = gettid();

  log_t log;
  log.tfd = output_fd;
  log.amfd_data = nullptr;

  char thread_name[16];
  read_with_default("/proc/self/comm", thread_name, sizeof(thread_name), "<unknown>");
  log_thread_name(&log, tid, thread_name);

  std::unique_ptr<Backtrace> backtrace(Backtrace::Create(pid, tid));
  if (backtrace->Unwind(0, ucontext)) {
    dump_backtrace_to_log(backtrace.get(), &log, "  ");
  } else {
    ALOGE("Unwind failed: tid = %d: %s", tid,
          backtrace->GetErrorString(backtrace->GetError()).c_str());
  }
}

void dump_backtrace_header(int output_fd) {
  log_t log;
  log.tfd = output_fd;
  log.amfd_data = nullptr;

  char process_name[128];
  read_with_default("/proc/self/cmdline", process_name, sizeof(process_name), "<unknown>");
  dump_process_header(&log, getpid(), process_name);
}

void dump_backtrace_footer(int output_fd) {
  log_t log;
  log.tfd = output_fd;
  log.amfd_data = nullptr;

  dump_process_footer(&log, getpid());
}

void dump_backtrace_to_log(Backtrace* backtrace, log_t* log, const char* prefix) {
  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    _LOG(log, logtype::BACKTRACE, "%s%s\n", prefix, backtrace->FormatFrameData(i).c_str());
  }
}
