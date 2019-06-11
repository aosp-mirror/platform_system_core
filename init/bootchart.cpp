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

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include <android-base/chrono_utils.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>

using android::base::StringPrintf;
using android::base::boot_clock;
using namespace std::chrono_literals;

namespace android {
namespace init {

static std::thread* g_bootcharting_thread;

static std::mutex g_bootcharting_finished_mutex;
static std::condition_variable g_bootcharting_finished_cv;
static bool g_bootcharting_finished;

static long long get_uptime_jiffies() {
    constexpr int64_t kNanosecondsPerJiffy = 10000000;
    boot_clock::time_point uptime = boot_clock::now();
    return uptime.time_since_epoch().count() / kNanosecondsPerJiffy;
}

static std::unique_ptr<FILE, decltype(&fclose)> fopen_unique(const char* filename,
                                                             const char* mode) {
  std::unique_ptr<FILE, decltype(&fclose)> result(fopen(filename, mode), fclose);
  if (!result) PLOG(ERROR) << "bootchart: failed to open " << filename;
  return result;
}

static void log_header() {
  char date[32];
  time_t now_t = time(NULL);
  struct tm now = *localtime(&now_t);
  strftime(date, sizeof(date), "%F %T", &now);

  utsname uts;
  if (uname(&uts) == -1) return;

  std::string fingerprint = android::base::GetProperty("ro.build.fingerprint", "");
  if (fingerprint.empty()) return;

  std::string kernel_cmdline;
  android::base::ReadFileToString("/proc/cmdline", &kernel_cmdline);

  auto fp = fopen_unique("/data/bootchart/header", "we");
  if (!fp) return;
  fprintf(&*fp, "version = Android init 0.8\n");
  fprintf(&*fp, "title = Boot chart for Android (%s)\n", date);
  fprintf(&*fp, "system.uname = %s %s %s %s\n", uts.sysname, uts.release, uts.version, uts.machine);
  fprintf(&*fp, "system.release = %s\n", fingerprint.c_str());
  // TODO: use /proc/cpuinfo "model name" line for x86, "Processor" line for arm.
  fprintf(&*fp, "system.cpu = %s\n", uts.machine);
  fprintf(&*fp, "system.kernel.options = %s\n", kernel_cmdline.c_str());
}

static void log_uptime(FILE* log) {
  fprintf(log, "%lld\n", get_uptime_jiffies());
}

static void log_file(FILE* log, const char* procfile) {
  log_uptime(log);

  std::string content;
  if (android::base::ReadFileToString(procfile, &content)) {
    fprintf(log, "%s\n", content.c_str());
  }
}

static void log_processes(FILE* log) {
  log_uptime(log);

  std::unique_ptr<DIR, int(*)(DIR*)> dir(opendir("/proc"), closedir);
  struct dirent* entry;
  while ((entry = readdir(dir.get())) != NULL) {
    // Only match numeric values.
    int pid = atoi(entry->d_name);
    if (pid == 0) continue;

    // /proc/<pid>/stat only has truncated task names, so get the full
    // name from /proc/<pid>/cmdline.
    std::string cmdline;
    android::base::ReadFileToString(StringPrintf("/proc/%d/cmdline", pid), &cmdline);
    const char* full_name = cmdline.c_str(); // So we stop at the first NUL.

    // Read process stat line.
    std::string stat;
    if (android::base::ReadFileToString(StringPrintf("/proc/%d/stat", pid), &stat)) {
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

  fputc('\n', log);
}

static void bootchart_thread_main() {
  LOG(INFO) << "Bootcharting started";

  // Open log files.
  auto stat_log = fopen_unique("/data/bootchart/proc_stat.log", "we");
  if (!stat_log) return;
  auto proc_log = fopen_unique("/data/bootchart/proc_ps.log", "we");
  if (!proc_log) return;
  auto disk_log = fopen_unique("/data/bootchart/proc_diskstats.log", "we");
  if (!disk_log) return;

  log_header();

  while (true) {
    {
      std::unique_lock<std::mutex> lock(g_bootcharting_finished_mutex);
      g_bootcharting_finished_cv.wait_for(lock, 200ms);
      if (g_bootcharting_finished) break;
    }

    log_file(&*stat_log, "/proc/stat");
    log_file(&*disk_log, "/proc/diskstats");
    log_processes(&*proc_log);
  }

  LOG(INFO) << "Bootcharting finished";
}

static Result<void> do_bootchart_start() {
    // We don't care about the content, but we do care that /data/bootchart/enabled actually exists.
    std::string start;
    if (!android::base::ReadFileToString("/data/bootchart/enabled", &start)) {
        LOG(VERBOSE) << "Not bootcharting";
        return {};
    }

    g_bootcharting_thread = new std::thread(bootchart_thread_main);
    return {};
}

static Result<void> do_bootchart_stop() {
    if (!g_bootcharting_thread) return {};

    // Tell the worker thread it's time to quit.
    {
        std::lock_guard<std::mutex> lock(g_bootcharting_finished_mutex);
        g_bootcharting_finished = true;
        g_bootcharting_finished_cv.notify_one();
    }

    g_bootcharting_thread->join();
    delete g_bootcharting_thread;
    g_bootcharting_thread = nullptr;
    return {};
}

Result<void> do_bootchart(const BuiltinArguments& args) {
    if (args[1] == "start") return do_bootchart_start();
    return do_bootchart_stop();
}

}  // namespace init
}  // namespace android
