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

#include <gtest/gtest.h>

#include "collectors/cpu_usage_collector.h"
#include "metrics/metrics_library_mock.h"


TEST(CpuUsageTest, ParseProcStat) {
  MetricsLibraryMock metrics_lib_mock;
  CpuUsageCollector collector(&metrics_lib_mock);
  std::vector<std::string> invalid_contents = {
    "",
    // First line does not start with cpu.
    "spu  17191 11 36579 151118 289 0 2 0 0 0\n"
    "cpu0 1564 2 866 48650 68 0 2 0 0 0\n"
    "cpu1 14299 0 35116 1844 81 0 0 0 0 0\n",
    // One of the field is not a number.
    "cpu  a17191 11 36579 151118 289 0 2 0 0 0",
    // To many numbers in the first line.
    "cpu  17191 11 36579 151118 289 0 2 0 0 0 102"
  };

  uint64_t user, nice, system;
  for (int i = 0; i < invalid_contents.size(); i++) {
    ASSERT_FALSE(collector.ParseProcStat(invalid_contents[i], &user, &nice,
                                         &system));
  }

  ASSERT_TRUE(collector.ParseProcStat(
      std::string("cpu  17191 11 36579 151118 289 0 2 0 0 0"),
      &user, &nice, &system));
  ASSERT_EQ(17191, user);
  ASSERT_EQ(11, nice);
  ASSERT_EQ(36579, system);
}
