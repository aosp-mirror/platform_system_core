/*
 * Copyright (C) 2017 The Android Open Source Project
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

#include "android-base/chrono_utils.h"

#include <err.h>
#include <time.h>

#include <chrono>

#include <gtest/gtest.h>

namespace android {
namespace base {

#if defined(__linux__)
std::chrono::seconds GetBootTimeSeconds() {
  struct timespec now;
  if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) {
    err(1, "clock_gettime failed");
  }

  auto now_tp = boot_clock::time_point(std::chrono::seconds(now.tv_sec) +
                                       std::chrono::nanoseconds(now.tv_nsec));
  return std::chrono::duration_cast<std::chrono::seconds>(now_tp.time_since_epoch());
}

// Tests (at least) the seconds accuracy of the boot_clock::now() method.
TEST(ChronoUtilsTest, BootClockNowSeconds) {
  auto now = GetBootTimeSeconds();
  auto boot_seconds =
      std::chrono::duration_cast<std::chrono::seconds>(boot_clock::now().time_since_epoch());
  EXPECT_EQ(now, boot_seconds);
}
#endif  // defined(__linux__)

}  // namespace base
}  // namespace android
