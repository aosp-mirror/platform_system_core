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

#include <stdarg.h>

#include <string>

#include <base/stringprintf.h>

std::string g_fake_log_buf;

std::string g_fake_log_print;

void resetLogs() {
  g_fake_log_buf = "";
  g_fake_log_print = "";
}

extern "C" int __android_log_buf_write(int, int, const char* tag, const char* msg) {
  g_fake_log_buf += tag;
  g_fake_log_buf += ' ';
  g_fake_log_buf += msg;
  return 1;
}

std::string getFakeLogBuf() {
  return g_fake_log_buf;
}

extern "C" int __android_log_print(int, const char* tag, const char* fmt, ...) {
  g_fake_log_print += tag;
  g_fake_log_print += ' ';

  va_list ap;
  va_start(ap, fmt);
  android::base::StringAppendV(&g_fake_log_print, fmt, ap);
  va_end(ap);

  g_fake_log_print += '\n';

  return 1;
}

std::string getFakeLogPrint() {
  return g_fake_log_print;
}
