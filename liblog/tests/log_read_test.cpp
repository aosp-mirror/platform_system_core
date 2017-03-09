/*
 * Copyright (C) 2013-2017 The Android Open Source Project
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

#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <string>

#include <android-base/stringprintf.h>
#include <android/log.h>  // minimal logging API
#include <gtest/gtest.h>
// Test the APIs in this standalone include file
#include <log/log_read.h>
// Do not use anything in log/log_time.h despite side effects of the above.

TEST(liblog, __android_log_write__android_logger_list_read) {
#ifdef __ANDROID__
  pid_t pid = getpid();

  struct logger_list* logger_list;
  ASSERT_TRUE(
      NULL !=
      (logger_list = android_logger_list_open(
           LOG_ID_MAIN, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 1000, pid)));

  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  std::string buf = android::base::StringPrintf("pid=%u ts=%ld.%09ld", pid,
                                                ts.tv_sec, ts.tv_nsec);
  static const char tag[] =
      "liblog.__android_log_write__android_logger_list_read";
  static const char prio = ANDROID_LOG_DEBUG;
  ASSERT_LT(0, __android_log_write(prio, tag, buf.c_str()));
  usleep(1000000);

  buf = std::string(&prio, sizeof(prio)) + tag + std::string("", 1) + buf +
        std::string("", 1);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) break;

    EXPECT_EQ(log_msg.entry.pid, pid);
    // There may be a future where we leak "liblog" tagged LOG_ID_EVENT
    // binary messages through so that logger losses can be correlated?
    EXPECT_EQ(log_msg.id(), LOG_ID_MAIN);

    if (log_msg.entry.len != buf.length()) continue;

    if (buf != std::string(log_msg.msg(), log_msg.entry.len)) continue;

    ++count;
  }
  android_logger_list_close(logger_list);

  EXPECT_EQ(1, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, android_logger_get_) {
#ifdef __ANDROID__
  // This test assumes the log buffers are filled with noise from
  // normal operations. It will fail if done immediately after a
  // logcat -c.
  struct logger_list* logger_list =
      android_logger_list_alloc(ANDROID_LOG_WRONLY, 0, 0);

  for (int i = LOG_ID_MIN; i < LOG_ID_MAX; ++i) {
    log_id_t id = static_cast<log_id_t>(i);
    const char* name = android_log_id_to_name(id);
    if (id != android_name_to_log_id(name)) {
      continue;
    }
    fprintf(stderr, "log buffer %s\r", name);
    struct logger* logger;
    EXPECT_TRUE(NULL != (logger = android_logger_open(logger_list, id)));
    EXPECT_EQ(id, android_logger_get_id(logger));
    ssize_t get_log_size = android_logger_get_log_size(logger);
    /* security buffer is allowed to be denied */
    if (strcmp("security", name)) {
      EXPECT_LT(0, get_log_size);
      /* crash buffer is allowed to be empty, that is actually healthy! */
      EXPECT_LE((strcmp("crash", name)) != 0,
                android_logger_get_log_readable_size(logger));
    } else {
      EXPECT_NE(0, get_log_size);
      if (get_log_size < 0) {
        EXPECT_GT(0, android_logger_get_log_readable_size(logger));
      } else {
        EXPECT_LE(0, android_logger_get_log_readable_size(logger));
      }
    }
    EXPECT_LT(0, android_logger_get_log_version(logger));
  }

  android_logger_list_close(logger_list);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
