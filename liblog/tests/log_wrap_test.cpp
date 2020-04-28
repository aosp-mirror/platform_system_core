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

#include <android-base/chrono_utils.h>
#include <android-base/stringprintf.h>
#include <android/log.h>  // minimal logging API
#include <gtest/gtest.h>
#include <log/log_properties.h>
#include <log/log_read.h>
#include <log/log_time.h>
#include <log/log_transport.h>

#ifdef __ANDROID__
static void read_with_wrap() {
  android_set_log_transport(LOGGER_LOGD);

  // Read the last line in the log to get a starting timestamp. We're assuming
  // the log is not empty.
  const int mode = ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK;
  struct logger_list* logger_list =
      android_logger_list_open(LOG_ID_MAIN, mode, 1000, 0);

  ASSERT_NE(logger_list, nullptr);

  log_msg log_msg;
  int ret = android_logger_list_read(logger_list, &log_msg);
  android_logger_list_close(logger_list);
  ASSERT_GT(ret, 0);

  log_time start(log_msg.entry.sec, log_msg.entry.nsec);
  ASSERT_NE(start, log_time());

  logger_list =
      android_logger_list_alloc_time(mode | ANDROID_LOG_WRAP, start, 0);
  ASSERT_NE(logger_list, nullptr);

  struct logger* logger = android_logger_open(logger_list, LOG_ID_MAIN);
  EXPECT_NE(logger, nullptr);
  if (logger) {
    android_logger_list_read(logger_list, &log_msg);
  }

  android_logger_list_close(logger_list);
}

static void caught_signal(int /* signum */) {
}
#endif

// b/64143705 confirm fixed
TEST(liblog, wrap_mode_blocks) {
#ifdef __ANDROID__

  android::base::Timer timer;

  // The read call is expected to take up to 2 hours in the happy case.
  // We only want to make sure it waits for longer than 30s, but we can't
  // use an alarm as the implementation uses it. So we run the test in
  // a separate process.
  pid_t pid = fork();

  if (pid == 0) {
    // child
    read_with_wrap();
    _exit(0);
  }

  struct sigaction ignore, old_sigaction;
  memset(&ignore, 0, sizeof(ignore));
  ignore.sa_handler = caught_signal;
  sigemptyset(&ignore.sa_mask);
  sigaction(SIGALRM, &ignore, &old_sigaction);
  alarm(45);

  bool killed = false;
  for (;;) {
    siginfo_t info = {};
    // This wait will succeed if the child exits, or fail with EINTR if the
    // alarm goes off first - a loose approximation to a timed wait.
    int ret = waitid(P_PID, pid, &info, WEXITED);
    if (ret >= 0 || errno != EINTR) {
      EXPECT_EQ(ret, 0);
      if (!killed) {
        EXPECT_EQ(info.si_status, 0);
      }
      break;
    }
    unsigned int alarm_left = alarm(0);
    if (alarm_left > 0) {
      alarm(alarm_left);
    } else {
      kill(pid, SIGTERM);
      killed = true;
    }
  }

  alarm(0);
  EXPECT_GT(timer.duration(), std::chrono::seconds(40));
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
