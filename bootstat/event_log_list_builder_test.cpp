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

#include "event_log_list_builder.h"

#include <inttypes.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <log/log.h>

using testing::ElementsAreArray;

TEST(EventLogListBuilder, Empty) {
  EventLogListBuilder builder;

  const uint8_t EXPECTED_LOG[] = {
    EVENT_TYPE_LIST,
    0,  // Number of items in the list.
  };

  std::unique_ptr<uint8_t[]> log;
  size_t size;
  builder.Release(&log, &size);
  EXPECT_EQ(2U, size);

  uint8_t* log_data = log.get();
  EXPECT_THAT(std::vector<uint8_t>(log_data, log_data + size),
              ElementsAreArray(EXPECTED_LOG));
}

TEST(EventLogListBuilder, SingleInt) {
  EventLogListBuilder builder;

  const uint8_t EXPECTED_LOG[] = {
    EVENT_TYPE_LIST,
    1,                // Number of items in the list.
    EVENT_TYPE_INT,
    42, 0, 0, 0,      // 4 byte integer value.
  };

  builder.Append(42);

  std::unique_ptr<uint8_t[]> log;
  size_t size;
  builder.Release(&log, &size);
  EXPECT_EQ(7U, size);

  uint8_t* log_data = log.get();
  EXPECT_THAT(std::vector<uint8_t>(log_data, log_data + size),
              ElementsAreArray(EXPECTED_LOG));
}

TEST(EventLogListBuilder, SingleString) {
  EventLogListBuilder builder;

  const uint8_t EXPECTED_LOG[] = {
    EVENT_TYPE_LIST,
    1,                        // Number of items in the list.
    EVENT_TYPE_STRING,
    5, 0, 0, 0,               // 4 byte length of the string.
    'D', 'r', 'o', 'i', 'd',
  };

  builder.Append("Droid");

  std::unique_ptr<uint8_t[]> log;
  size_t size;
  builder.Release(&log, &size);
  EXPECT_EQ(12U, size);

  uint8_t* log_data = log.get();
  EXPECT_THAT(std::vector<uint8_t>(log_data, log_data + size),
              ElementsAreArray(EXPECTED_LOG));
}

TEST(EventLogListBuilder, IntThenString) {
  EventLogListBuilder builder;

  const uint8_t EXPECTED_LOG[] = {
    EVENT_TYPE_LIST,
    2,                        // Number of items in the list.
    EVENT_TYPE_INT,
    42, 0, 0, 0,              // 4 byte integer value.
    EVENT_TYPE_STRING,
    5, 0, 0, 0,               // 4 byte length of the string.
    'D', 'r', 'o', 'i', 'd',
  };

  builder.Append(42);
  builder.Append("Droid");

  std::unique_ptr<uint8_t[]> log;
  size_t size;
  builder.Release(&log, &size);
  EXPECT_EQ(17U, size);

  uint8_t* log_data = log.get();
  EXPECT_THAT(std::vector<uint8_t>(log_data, log_data + size),
              ElementsAreArray(EXPECTED_LOG));
}
