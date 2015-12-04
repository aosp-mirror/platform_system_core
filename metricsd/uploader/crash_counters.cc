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

#include "uploader/crash_counters.h"

CrashCounters::CrashCounters()
    : kernel_crashes_(0), unclean_shutdowns_(0), user_crashes_(0) {}

void CrashCounters::IncrementKernelCrashCount() {
  kernel_crashes_++;
}

unsigned int CrashCounters::GetAndResetKernelCrashCount() {
  return kernel_crashes_.exchange(0);
}

void CrashCounters::IncrementUncleanShutdownCount() {
  unclean_shutdowns_++;
}

unsigned int CrashCounters::GetAndResetUncleanShutdownCount() {
  return unclean_shutdowns_.exchange(0);
}

void CrashCounters::IncrementUserCrashCount() {
  user_crashes_++;
}

unsigned int CrashCounters::GetAndResetUserCrashCount() {
  return user_crashes_.exchange(0);
}
