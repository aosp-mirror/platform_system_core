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

#pragma once

#include <condition_variable>

#include "sysdeps/mutex.h"

#if defined(_WIN32)

#include <windows.h>

#include <android-base/macros.h>

// The prebuilt version of mingw we use doesn't support condition_variable.
// Therefore, implement our own using the Windows primitives.
// Put them directly into the std namespace, so that when they're actually available, the build
// breaks until they're removed.

namespace std {

class condition_variable {
  public:
    condition_variable() {
        InitializeConditionVariable(&cond_);
    }

    void wait(std::unique_lock<std::mutex>& lock) {
        std::mutex *m = lock.mutex();
        m->lock_count_--;
        SleepConditionVariableCS(&cond_, m->native_handle(), INFINITE);
        m->lock_count_++;
    }

    void notify_one() {
        WakeConditionVariable(&cond_);
    }

  private:
    CONDITION_VARIABLE cond_;

    DISALLOW_COPY_AND_ASSIGN(condition_variable);
};

}

#endif  // defined(_WIN32)
