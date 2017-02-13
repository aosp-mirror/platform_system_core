/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "metricslogger/metrics_logger.h"

#include <gtest/gtest.h>

TEST(MetricsLoggerTest, AddSingleBootEvent) {
  android::metricslogger::LogHistogram("test_event", 42);
  /*pid_t pid = getpid();
  struct logger_list *logger_list = android_logger_list_open(
      LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 0, pid);

  logger_list = NULL;
  log_msg log_msg;
  android_logger_list_read(logger_list, &log_msg);
  std::cout << log_msg.len() << std::endl;*/
}
