/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <log/log.h>
#include <private/android_logger.h>

#include <stdlib.h>
#include <unistd.h>

#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>
#include <gtest/gtest.h>

using android::base::StringPrintf;
using android::base::StringReplace;

void GenerateLogContent() {
  __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_VERBOSE, "tag", "verbose main");
  __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_INFO, "tag", "info main");
  __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_ERROR, "tag", "error main");

  __android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_VERBOSE, "tag", "verbose radio");
  __android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_INFO, "tag", "info radio");
  __android_log_buf_print(LOG_ID_RADIO, ANDROID_LOG_ERROR, "tag", "error radio");

  __android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_VERBOSE, "tag", "verbose system");
  __android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_INFO, "tag", "info system");
  __android_log_buf_print(LOG_ID_SYSTEM, ANDROID_LOG_ERROR, "tag", "error system");

  __android_log_buf_print(LOG_ID_CRASH, ANDROID_LOG_VERBOSE, "tag", "verbose crash");
  __android_log_buf_print(LOG_ID_CRASH, ANDROID_LOG_INFO, "tag", "info crash");
  __android_log_buf_print(LOG_ID_CRASH, ANDROID_LOG_ERROR, "tag", "error crash");
}

std::string GetPidString() {
  int pid = getpid();
  return StringPrintf("%5d", pid);
}

TEST(liblog, default_write) {
  setenv("ANDROID_PRINTF_LOG", "brief", true);
  CapturedStderr captured_stderr;

  GenerateLogContent();

  std::string expected_output = StringReplace(R"init(I/tag     (<pid>): info main
E/tag     (<pid>): error main
I/tag     (<pid>): info radio
E/tag     (<pid>): error radio
I/tag     (<pid>): info system
E/tag     (<pid>): error system
I/tag     (<pid>): info crash
E/tag     (<pid>): error crash
)init",
                                              "<pid>", GetPidString(), true);

  EXPECT_EQ(expected_output, captured_stderr.str());
}

TEST(liblog, format) {
  setenv("ANDROID_PRINTF_LOG", "process", true);
  CapturedStderr captured_stderr;

  GenerateLogContent();

  std::string expected_output = StringReplace(R"init(I(<pid>) info main  (tag)
E(<pid>) error main  (tag)
I(<pid>) info radio  (tag)
E(<pid>) error radio  (tag)
I(<pid>) info system  (tag)
E(<pid>) error system  (tag)
I(<pid>) info crash  (tag)
E(<pid>) error crash  (tag)
)init",
                                              "<pid>", GetPidString(), true);

  EXPECT_EQ(expected_output, captured_stderr.str());
  captured_stderr.Stop();
  captured_stderr.Reset();
  captured_stderr.Start();

  // Changing the environment after starting writing doesn't change the format.
  setenv("ANDROID_PRINTF_LOG", "brief", true);
  GenerateLogContent();
  EXPECT_EQ(expected_output, captured_stderr.str());
  captured_stderr.Stop();
  captured_stderr.Reset();
  captured_stderr.Start();

  // However calling __android_log_close() does reset logging and allow changing the format.
  __android_log_close();
  GenerateLogContent();

  expected_output = StringReplace(R"init(I/tag     (<pid>): info main
E/tag     (<pid>): error main
I/tag     (<pid>): info radio
E/tag     (<pid>): error radio
I/tag     (<pid>): info system
E/tag     (<pid>): error system
I/tag     (<pid>): info crash
E/tag     (<pid>): error crash
)init",
                                  "<pid>", GetPidString(), true);

  EXPECT_EQ(expected_output, captured_stderr.str());
}

TEST(liblog, filter) {
  setenv("ANDROID_PRINTF_LOG", "brief", true);
  setenv("ANDROID_LOG_TAGS", "*:w verbose_tag:v debug_tag:d", true);
  CapturedStderr captured_stderr;

  auto generate_logs = [](log_id_t log_id) {
    // Check that we show verbose logs when requesting for a given tag.
    __android_log_buf_print(log_id, ANDROID_LOG_VERBOSE, "verbose_tag", "verbose verbose_tag");
    __android_log_buf_print(log_id, ANDROID_LOG_ERROR, "verbose_tag", "error verbose_tag");

    // Check that we don't show verbose logs when explicitly requesting debug+ for a given tag.
    __android_log_buf_print(log_id, ANDROID_LOG_VERBOSE, "debug_tag", "verbose debug_tag");
    __android_log_buf_print(log_id, ANDROID_LOG_DEBUG, "debug_tag", "debug debug_tag");
    __android_log_buf_print(log_id, ANDROID_LOG_ERROR, "debug_tag", "error debug_tag");

    // Check that we don't show info logs when requesting globally warn+.
    __android_log_buf_print(log_id, ANDROID_LOG_INFO, "default_tag", "info default_tag");
    __android_log_buf_print(log_id, ANDROID_LOG_WARN, "default_tag", "warn default_tag");
    __android_log_buf_print(log_id, ANDROID_LOG_ERROR, "default_tag", "error default_tag");
  };

  auto expected_output = StringReplace(R"init(V/verbose_tag(<pid>): verbose verbose_tag
E/verbose_tag(<pid>): error verbose_tag
D/debug_tag(<pid>): debug debug_tag
E/debug_tag(<pid>): error debug_tag
W/default_tag(<pid>): warn default_tag
E/default_tag(<pid>): error default_tag
)init",
                                       "<pid>", GetPidString(), true);

  auto test_all_logs = [&] {
    for (auto log_id : {LOG_ID_MAIN, LOG_ID_SYSTEM, LOG_ID_RADIO, LOG_ID_CRASH}) {
      generate_logs(log_id);
      EXPECT_EQ(expected_output, captured_stderr.str());
      captured_stderr.Stop();
      captured_stderr.Reset();
      captured_stderr.Start();
    }
  };

  test_all_logs();

  // Changing the environment after starting writing doesn't change the filter.
  setenv("ANDROID_LOG_TAGS", "*:e", true);
  test_all_logs();

  // However calling __android_log_close() does reset logging and allow changing the format.
  __android_log_close();
  expected_output = StringReplace(R"init(E/verbose_tag(<pid>): error verbose_tag
E/debug_tag(<pid>): error debug_tag
E/default_tag(<pid>): error default_tag
)init",
                                  "<pid>", GetPidString(), true);
  test_all_logs();
}

TEST(liblog, kernel_no_write) {
  CapturedStderr captured_stderr;
  __android_log_buf_print(LOG_ID_KERNEL, ANDROID_LOG_ERROR, "tag", "kernel error");
  EXPECT_EQ("", captured_stderr.str());
}

TEST(liblog, binary_no_write) {
  CapturedStderr captured_stderr;
  __android_log_buf_print(LOG_ID_EVENTS, ANDROID_LOG_ERROR, "tag", "error events");
  __android_log_buf_print(LOG_ID_STATS, ANDROID_LOG_ERROR, "tag", "error stats");
  __android_log_buf_print(LOG_ID_SECURITY, ANDROID_LOG_ERROR, "tag", "error security");

  __android_log_bswrite(0x12, "events");
  __android_log_stats_bwrite(0x34, "stats", strlen("stats"));
  __android_log_security_bswrite(0x56, "security");

  EXPECT_EQ("", captured_stderr.str());
}
