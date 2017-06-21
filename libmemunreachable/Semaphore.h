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

#ifndef LIBMEMUNREACHABLE_SEMAPHORE_H_
#define LIBMEMUNREACHABLE_SEMAPHORE_H_

#include <chrono>
#include <mutex>

#include "android-base/macros.h"

namespace android {

class Semaphore {
 public:
  explicit Semaphore(int count = 0) : count_(count) {}
  ~Semaphore() = default;

  void Wait(std::chrono::milliseconds ms) {
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait_for(lk, ms, [&] {
      if (count_ > 0) {
        count_--;
        return true;
      }
      return false;
    });
  }
  void Post() {
    {
      std::lock_guard<std::mutex> lk(m_);
      count_++;
    }
    cv_.notify_one();
  }

 private:
  DISALLOW_COPY_AND_ASSIGN(Semaphore);

  int count_;
  std::mutex m_;
  std::condition_variable cv_;
};

}  // namespace android

#endif  // LIBMEMUNREACHABLE_SEMAPHORE_H_
