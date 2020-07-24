/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "util.h"

#include <sys/socket.h>
#include <time.h>

#include <string>
#include <utility>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <cutils/sockets.h>
#include "protocol.h"

std::string get_process_name(pid_t pid) {
  std::string result = "<unknown>";
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/cmdline", pid), &result);
  return result;
}

std::string get_thread_name(pid_t tid) {
  std::string result = "<unknown>";
  android::base::ReadFileToString(android::base::StringPrintf("/proc/%d/comm", tid), &result);
  return android::base::Trim(result);
}

std::string get_timestamp() {
  timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);

  tm tm;
  localtime_r(&ts.tv_sec, &tm);

  char buf[strlen("1970-01-01 00:00:00.123456789+0830") + 1];
  char* s = buf;
  size_t sz = sizeof(buf), n;
  n = strftime(s, sz, "%F %H:%M", &tm), s += n, sz -= n;
  n = snprintf(s, sz, ":%02d.%09ld", tm.tm_sec, ts.tv_nsec), s += n, sz -= n;
  n = strftime(s, sz, "%z", &tm), s += n, sz -= n;
  return buf;
}
