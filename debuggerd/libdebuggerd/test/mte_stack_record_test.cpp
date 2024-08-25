/*
 * Copyright (C) 2024 The Android Open Source Project
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
#if defined(__aarch64__)

#include <stdint.h>
#include <sys/mman.h>

#include <optional>

#include "bionic/mte.h"
#include "bionic/page.h"
#include "unwindstack/AndroidUnwinder.h"
#include "unwindstack/Memory.h"

#include <android-base/test_utils.h>
#include "gtest/gtest.h"

#include "libdebuggerd/tombstone.h"

struct ScopedUnmap {
  void* ptr;
  size_t size;
  ~ScopedUnmap() { munmap(ptr, size); }
};

class MteStackHistoryTest : public ::testing::TestWithParam<int> {
  void SetUp() override {
#if !defined(__aarch64__)
    GTEST_SKIP();
#endif
    SKIP_WITH_HWASAN;
    unwinder.emplace();
    unwindstack::ErrorData E;
    ASSERT_TRUE(unwinder->Initialize(E));
  }

 protected:
  // std::optional so we don't construct it for the SKIP cases.
  std::optional<unwindstack::AndroidLocalUnwinder> unwinder;
};

TEST(MteStackHistoryUnwindTest, TestOne) {
#if !defined(__aarch64__)
  GTEST_SKIP();
#endif
  SKIP_WITH_HWASAN;
  size_t size = stack_mte_ringbuffer_size(0);
  char* data = static_cast<char*>(stack_mte_ringbuffer_allocate(0, nullptr));
  ScopedUnmap s{data, size};

  uintptr_t taggedfp = (1ULL << 56) | 1;
  uintptr_t pc = reinterpret_cast<uintptr_t>(&memcpy);
  memcpy(data, &pc, sizeof(pc));
  memcpy(data + 8, &taggedfp, sizeof(taggedfp));

  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  void* tls[4] = {data + 16};

  unwindstack::AndroidLocalUnwinder unwinder;
  unwindstack::ErrorData E;
  unwinder.Initialize(E);
  StackHistoryBuffer shb;
  dump_stack_history(&unwinder, reinterpret_cast<uintptr_t>(&tls[3]), shb, /* nounwind= */ false);
  ASSERT_EQ(shb.entries_size(), 1);
  const StackHistoryBufferEntry& e = shb.entries(0);
  EXPECT_EQ(e.addr().pc(), pc);
  EXPECT_EQ(e.addr().file_name(), "/apex/com.android.runtime/lib64/bionic/libc.so");
  EXPECT_EQ(e.fp(), 1ULL);
  EXPECT_EQ(e.tag(), 1ULL);
}

TEST_P(MteStackHistoryTest, TestEmpty) {
  int size_cls = GetParam();
  size_t size = stack_mte_ringbuffer_size(size_cls);
  void* data = stack_mte_ringbuffer_allocate(size_cls, nullptr);
  ScopedUnmap s{data, size};
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  void* tls[4] = {data};

  StackHistoryBuffer shb;
  dump_stack_history(&*unwinder, reinterpret_cast<uintptr_t>(&tls[3]), shb, /* nounwind= */ true);
  EXPECT_EQ(shb.entries_size(), 0);
}

TEST_P(MteStackHistoryTest, TestFull) {
  int size_cls = GetParam();
  size_t size = stack_mte_ringbuffer_size(size_cls);
  char* data = static_cast<char*>(stack_mte_ringbuffer_allocate(size_cls, nullptr));
  ScopedUnmap s{data, size};
  uintptr_t itr = 1;
  for (char* d = data; d < &data[size]; d += 16) {
    uintptr_t taggedfp = ((itr & 15) << 56) | itr;
    uintptr_t pc = itr;
    memcpy(d, &pc, sizeof(pc));
    memcpy(d + 8, &taggedfp, sizeof(taggedfp));
    ++itr;
  }
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  // Because the buffer is full, and we point at one past the last inserted element,
  // due to wrap-around we point at the beginning of the buffer.
  void* tls[4] = {data};

  StackHistoryBuffer shb;
  dump_stack_history(&*unwinder, reinterpret_cast<uintptr_t>(&tls[3]), shb, /* nounwind= */ true);
  EXPECT_EQ(static_cast<size_t>(shb.entries_size()), size / 16);
  for (const auto& entry : shb.entries()) {
    EXPECT_EQ(entry.addr().pc(), --itr);
    EXPECT_EQ(entry.addr().pc(), entry.fp());
    EXPECT_EQ(entry.addr().pc() & 15, entry.tag());
  }
}

TEST_P(MteStackHistoryTest, TestHalfFull) {
  int size_cls = GetParam();
  size_t size = stack_mte_ringbuffer_size(size_cls);
  size_t half_size = size / 2;

  char* data = static_cast<char*>(stack_mte_ringbuffer_allocate(size_cls, nullptr));
  ScopedUnmap s{data, size};

  uintptr_t itr = 1;
  for (char* d = data; d < &data[half_size]; d += 16) {
    uintptr_t taggedfp = ((itr & 15) << 56) | itr;
    uintptr_t pc = itr;
    memcpy(d, &pc, sizeof(pc));
    memcpy(d + 8, &taggedfp, sizeof(taggedfp));
    ++itr;
  }
  // The MTE TLS is at TLS - 3, so we allocate 3 placeholders.
  void* tls[4] = {&data[half_size]};

  StackHistoryBuffer shb;
  dump_stack_history(&*unwinder, reinterpret_cast<uintptr_t>(&tls[3]), shb, /* nounwind= */ true);
  EXPECT_EQ(static_cast<size_t>(shb.entries_size()), half_size / 16);
  for (const auto& entry : shb.entries()) {
    EXPECT_EQ(entry.addr().pc(), --itr);
    EXPECT_EQ(entry.addr().pc(), entry.fp());
    EXPECT_EQ(entry.addr().pc() & 15, entry.tag());
  }
}

INSTANTIATE_TEST_SUITE_P(MteStackHistoryTestInstance, MteStackHistoryTest, testing::Range(0, 8));

#endif
