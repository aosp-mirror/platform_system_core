/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "../rwlock.h"

#include <chrono>
#include <shared_mutex>
#include <thread>

#include <gtest/gtest.h>

using namespace std::literals;

TEST(rwlock, reader_then_reader_lock) {
  RwLock lock;

  bool thread_ran = false;
  auto read_guard = std::shared_lock{lock};

  auto reader_thread = std::thread([&] {
    auto read_guard = std::shared_lock{lock};
    thread_ran = true;
  });

  auto end_time = std::chrono::steady_clock::now() + 1s;

  while (std::chrono::steady_clock::now() < end_time) {
    if (thread_ran) {
      break;
    }
  }

  EXPECT_EQ(true, thread_ran);

  // Unlock the lock in case something went wrong, to ensure that we can still join() the thread.
  read_guard.unlock();
  reader_thread.join();
}

template <template <typename> typename L1, template <typename> typename L2>
void TestBlockingLocks() {
  RwLock lock;

  bool thread_ran = false;
  auto read_guard = L1{lock};

  auto reader_thread = std::thread([&] {
    auto read_guard = L2{lock};
    thread_ran = true;
  });

  auto end_time = std::chrono::steady_clock::now() + 1s;

  while (std::chrono::steady_clock::now() < end_time) {
    if (thread_ran) {
      break;
    }
  }

  EXPECT_EQ(false, thread_ran);

  read_guard.unlock();
  reader_thread.join();

  EXPECT_EQ(true, thread_ran);
}

TEST(rwlock, reader_then_writer_lock) {
  TestBlockingLocks<std::shared_lock, std::unique_lock>();
}

TEST(rwlock, writer_then_reader_lock) {
  TestBlockingLocks<std::unique_lock, std::shared_lock>();
}

TEST(rwlock, writer_then_writer_lock) {
  TestBlockingLocks<std::unique_lock, std::unique_lock>();
}
