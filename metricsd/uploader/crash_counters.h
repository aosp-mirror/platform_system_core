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

#ifndef METRICSD_UPLOADER_CRASH_COUNTERS_H_
#define METRICSD_UPLOADER_CRASH_COUNTERS_H_

#include <atomic>

// This class is used to keep track of the crash counters.
// An instance of it will be used by both the binder thread (to increment the
// counters) and the uploader thread (to gather and reset the counters).
// As such, the internal counters are atomic uints to allow concurrent access.
class CrashCounters {
 public:
  CrashCounters();

  void IncrementKernelCrashCount();
  unsigned int GetAndResetKernelCrashCount();

  void IncrementUserCrashCount();
  unsigned int GetAndResetUserCrashCount();

  void IncrementUncleanShutdownCount();
  unsigned int GetAndResetUncleanShutdownCount();

 private:
  std::atomic_uint kernel_crashes_;
  std::atomic_uint unclean_shutdowns_;
  std::atomic_uint user_crashes_;
};

#endif  // METRICSD_UPLOADER_CRASH_COUNTERS_H_
