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

#include "uploader/metrics_hashes.h"

#include <base/format_macros.h>
#include <base/macros.h>
#include <base/strings/stringprintf.h>
#include <gtest/gtest.h>

namespace metrics {

// Make sure our ID hashes are the same as what we see on the server side.
TEST(MetricsUtilTest, HashMetricName) {
  static const struct {
    std::string input;
    std::string output;
  } cases[] = {
    {"Back", "0x0557fa923dcee4d0"},
    {"Forward", "0x67d2f6740a8eaebf"},
    {"NewTab", "0x290eb683f96572f1"},
  };

  for (size_t i = 0; i < arraysize(cases); ++i) {
    uint64_t hash = HashMetricName(cases[i].input);
    std::string hash_hex = base::StringPrintf("0x%016" PRIx64, hash);
    EXPECT_EQ(cases[i].output, hash_hex);
  }
}

}  // namespace metrics
