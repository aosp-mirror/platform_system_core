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

#include <time.h>

namespace android {
namespace base {

boot_clock::time_point boot_clock::now() {
  timespec ts;
  clockid_t clk_id;

#ifdef __ANDROID__
  clk_id = CLOCK_BOOTTIME;
#else
  // Darwin does not support CLOCK_BOOTTIME.  CLOCK_MONOTONIC is a sufficient
  // fallback; the only loss of precision is the time duration when the system
  // is suspended.
  clk_id = CLOCK_MONOTONIC;
#endif  // __ANDROID__

  clock_gettime(clk_id, &ts);
  return boot_clock::time_point(std::chrono::seconds(ts.tv_sec) +
                                std::chrono::nanoseconds(ts.tv_nsec));
}

}  // namespace base
}  // namespace android
