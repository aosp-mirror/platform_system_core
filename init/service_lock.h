/*
 * Copyright (C) 2020 The Android Open Source Project
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

#pragma once

#include <mutex>

#include <android-base/thread_annotations.h>

namespace android {
namespace init {

// This class exists to add thread annotations, since they're absent from std::recursive_mutex.

class CAPABILITY("mutex") RecursiveMutex {
  public:
    void lock() ACQUIRE() { mutex_.lock(); }
    void unlock() RELEASE() { mutex_.unlock(); }

  private:
    std::recursive_mutex mutex_;
};

extern RecursiveMutex service_lock;

}  // namespace init
}  // namespace android
