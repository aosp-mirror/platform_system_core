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

#include <sys/time.h>

#include <chrono>
#include <functional>

#include <ScopedDisableMalloc.h>
#include <gtest/gtest.h>

using namespace std::chrono_literals;

namespace android {

class DisableMallocTest : public ::testing::Test {
 protected:
  void alarm(std::chrono::microseconds us) {
    std::chrono::seconds s = std::chrono::duration_cast<std::chrono::seconds>(us);
    itimerval t = itimerval();
    t.it_value.tv_sec = s.count();
    t.it_value.tv_usec = (us - s).count();
    setitimer(ITIMER_REAL, &t, NULL);
  }
};

TEST_F(DisableMallocTest, reenable) {
  ASSERT_EXIT(
      {
        alarm(100ms);
        void* ptr1 = malloc(128);
        ASSERT_NE(ptr1, nullptr);
        free(ptr1);
        { ScopedDisableMalloc disable_malloc; }
        void* ptr2 = malloc(128);
        ASSERT_NE(ptr2, nullptr);
        free(ptr2);
        _exit(1);
      },
      ::testing::ExitedWithCode(1), "");
}

TEST_F(DisableMallocTest, deadlock_allocate) {
  ASSERT_DEATH(
      {
        void* ptr = malloc(128);
        ASSERT_NE(ptr, nullptr);
        free(ptr);
        {
          alarm(100ms);
          ScopedDisableMalloc disable_malloc;
          void* ptr = malloc(128);
          ASSERT_NE(ptr, nullptr);
          free(ptr);
        }
      },
      "");
}

TEST_F(DisableMallocTest, deadlock_new) {
  ASSERT_DEATH(
      {
        // C++ allows `new Foo` to be replaced with a stack allocation or merged
        // with future `new Foo` expressions, provided certain conditions are
        // met [expr.new/10]. None of this applies to `operator new(size_t)`.
        void* ptr = ::operator new(1);
        ASSERT_NE(ptr, nullptr);
        ::operator delete(ptr);
        {
          alarm(100ms);
          ScopedDisableMalloc disable_malloc;
          void* ptr = ::operator new(1);
          ASSERT_NE(ptr, nullptr);
          ::operator delete(ptr);
        }
      },
      "");
}

TEST_F(DisableMallocTest, deadlock_delete) {
  ASSERT_DEATH(
      {
        void* ptr = ::operator new(1);
        ASSERT_NE(ptr, nullptr);
        {
          alarm(250ms);
          ScopedDisableMalloc disable_malloc;
          ::operator delete(ptr);
        }
      },
      "");
}

TEST_F(DisableMallocTest, deadlock_free) {
  ASSERT_DEATH(
      {
        void* ptr = malloc(128);
        ASSERT_NE(ptr, nullptr);
        {
          alarm(100ms);
          ScopedDisableMalloc disable_malloc;
          free(ptr);
        }
      },
      "");
}

TEST_F(DisableMallocTest, deadlock_fork) {
  ASSERT_DEATH({
    {
      alarm(100ms);
      ScopedDisableMalloc disable_malloc;
      fork();
}
}, "");
}

}  // namespace android
