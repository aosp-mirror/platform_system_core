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

#include <sys/mman.h>
#include <unistd.h>

#include "HeapWalker.h"

#include <ScopedDisableMalloc.h>
#include <gtest/gtest.h>
#include "Allocator.h"

namespace android {

class HeapWalkerTest : public ::testing::Test {
 public:
  HeapWalkerTest() : disable_malloc_(), heap_() {}

  void TearDown() {
    ASSERT_TRUE(heap_.empty());
    if (!HasFailure()) {
      ASSERT_FALSE(disable_malloc_.timed_out());
    }
  }

 protected:
  ScopedDisableMallocTimeout disable_malloc_;
  Heap heap_;
};

TEST_F(HeapWalkerTest, allocation) {
  HeapWalker heap_walker(heap_);
  ASSERT_TRUE(heap_walker.Allocation(3, 4));
  ASSERT_TRUE(heap_walker.Allocation(2, 3));
  ASSERT_TRUE(heap_walker.Allocation(4, 5));
  ASSERT_TRUE(heap_walker.Allocation(6, 7));
  ASSERT_TRUE(heap_walker.Allocation(0, 1));
}

TEST_F(HeapWalkerTest, overlap) {
  HeapWalker heap_walker(heap_);
  ASSERT_TRUE(heap_walker.Allocation(2, 3));
  ASSERT_TRUE(heap_walker.Allocation(3, 4));
  ASSERT_FALSE(heap_walker.Allocation(2, 3));
  ASSERT_FALSE(heap_walker.Allocation(1, 3));
  ASSERT_FALSE(heap_walker.Allocation(1, 4));
  ASSERT_FALSE(heap_walker.Allocation(1, 5));
  ASSERT_FALSE(heap_walker.Allocation(3, 4));
  ASSERT_FALSE(heap_walker.Allocation(3, 5));
  ASSERT_TRUE(heap_walker.Allocation(4, 5));
  ASSERT_TRUE(heap_walker.Allocation(1, 2));
}

TEST_F(HeapWalkerTest, zero) {
  HeapWalker heap_walker(heap_);
  ASSERT_TRUE(heap_walker.Allocation(2, 2));
  ASSERT_FALSE(heap_walker.Allocation(2, 2));
  ASSERT_TRUE(heap_walker.Allocation(3, 3));
  ASSERT_TRUE(heap_walker.Allocation(1, 1));
  ASSERT_FALSE(heap_walker.Allocation(2, 3));
}

#define buffer_begin(buffer) reinterpret_cast<uintptr_t>(buffer)
#define buffer_end(buffer) (reinterpret_cast<uintptr_t>(buffer) + sizeof(buffer))

TEST_F(HeapWalkerTest, leak) {
  void* buffer1[16]{};
  char buffer2[16]{};
  buffer1[0] = &buffer2[0] - sizeof(void*);
  buffer1[1] = &buffer2[15] + sizeof(void*);

  HeapWalker heap_walker(heap_);
  heap_walker.Allocation(buffer_begin(buffer2), buffer_end(buffer2));

  ASSERT_EQ(true, heap_walker.DetectLeaks());

  allocator::vector<Range> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, heap_walker.Leaked(leaked, 100, &num_leaks, &leaked_bytes));

  EXPECT_EQ(1U, num_leaks);
  EXPECT_EQ(16U, leaked_bytes);
  ASSERT_EQ(1U, leaked.size());
  EXPECT_EQ(buffer_begin(buffer2), leaked[0].begin);
  EXPECT_EQ(buffer_end(buffer2), leaked[0].end);
}

TEST_F(HeapWalkerTest, live) {
  const int from_buffer_entries = 4;
  const int to_buffer_bytes = 16;

  for (int i = 0; i < from_buffer_entries; i++) {
    for (int j = 0; j < to_buffer_bytes; j++) {
      void* buffer1[from_buffer_entries]{};
      char buffer2[to_buffer_bytes]{};
      buffer1[i] = &buffer2[j];

      HeapWalker heap_walker(heap_);
      heap_walker.Allocation(buffer_begin(buffer2), buffer_end(buffer2));
      heap_walker.Root(buffer_begin(buffer1), buffer_end(buffer1));

      ASSERT_EQ(true, heap_walker.DetectLeaks());

      allocator::vector<Range> leaked(heap_);
      size_t num_leaks = SIZE_MAX;
      size_t leaked_bytes = SIZE_MAX;
      ASSERT_EQ(true, heap_walker.Leaked(leaked, 100, &num_leaks, &leaked_bytes));

      EXPECT_EQ(0U, num_leaks);
      EXPECT_EQ(0U, leaked_bytes);
      EXPECT_EQ(0U, leaked.size());
    }
  }
}

TEST_F(HeapWalkerTest, unaligned) {
  const int from_buffer_entries = 4;
  const int to_buffer_bytes = 16;
  void* buffer1[from_buffer_entries]{};
  char buffer2[to_buffer_bytes]{};

  buffer1[1] = &buffer2;

  for (unsigned int i = 0; i < sizeof(uintptr_t); i++) {
    for (unsigned int j = 0; j < sizeof(uintptr_t); j++) {
      HeapWalker heap_walker(heap_);
      heap_walker.Allocation(buffer_begin(buffer2), buffer_end(buffer2));
      heap_walker.Root(buffer_begin(buffer1) + i, buffer_end(buffer1) - j);

      ASSERT_EQ(true, heap_walker.DetectLeaks());

      allocator::vector<Range> leaked(heap_);
      size_t num_leaks = SIZE_MAX;
      size_t leaked_bytes = SIZE_MAX;
      ASSERT_EQ(true, heap_walker.Leaked(leaked, 100, &num_leaks, &leaked_bytes));

      EXPECT_EQ(0U, num_leaks);
      EXPECT_EQ(0U, leaked_bytes);
      EXPECT_EQ(0U, leaked.size());
    }
  }
}

TEST_F(HeapWalkerTest, cycle) {
  void* buffer1;
  void* buffer2;

  buffer1 = &buffer2;
  buffer2 = &buffer1;

  HeapWalker heap_walker(heap_);
  heap_walker.Allocation(buffer_begin(buffer1), buffer_end(buffer1));
  heap_walker.Allocation(buffer_begin(buffer2), buffer_end(buffer2));

  ASSERT_EQ(true, heap_walker.DetectLeaks());

  allocator::vector<Range> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, heap_walker.Leaked(leaked, 100, &num_leaks, &leaked_bytes));

  EXPECT_EQ(2U, num_leaks);
  EXPECT_EQ(2 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(2U, leaked.size());
}

TEST_F(HeapWalkerTest, segv) {
  const size_t page_size = sysconf(_SC_PAGE_SIZE);
  void* buffer1 = mmap(NULL, page_size, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(buffer1, nullptr);
  void* buffer2;

  buffer2 = &buffer1;

  HeapWalker heap_walker(heap_);
  heap_walker.Allocation(buffer_begin(buffer1), buffer_begin(buffer1) + page_size);
  heap_walker.Root(buffer_begin(buffer2), buffer_end(buffer2));

  ASSERT_EQ(true, heap_walker.DetectLeaks());

  allocator::vector<Range> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, heap_walker.Leaked(leaked, 100, &num_leaks, &leaked_bytes));

  EXPECT_EQ(0U, num_leaks);
  EXPECT_EQ(0U, leaked_bytes);
  ASSERT_EQ(0U, leaked.size());
}

}  // namespace android
