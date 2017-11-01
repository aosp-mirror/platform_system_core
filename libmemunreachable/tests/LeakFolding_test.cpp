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

#include "LeakFolding.h"
#include "HeapWalker.h"

#include <ScopedDisableMalloc.h>
#include <gtest/gtest.h>
#include "Allocator.h"

namespace android {

class LeakFoldingTest : public ::testing::Test {
 public:
  LeakFoldingTest() : disable_malloc_(), heap_() {}

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

#define buffer_begin(buffer) reinterpret_cast<uintptr_t>(&(buffer)[0])
#define buffer_end(buffer) (reinterpret_cast<uintptr_t>(&(buffer)[0]) + sizeof(buffer))
#define ALLOCATION(heap_walker, buffer) \
  ASSERT_EQ(true, (heap_walker).Allocation(buffer_begin(buffer), buffer_end(buffer)))

TEST_F(LeakFoldingTest, one) {
  void* buffer1[1] = {nullptr};

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(1U, num_leaks);
  EXPECT_EQ(sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(1U, leaked.size());
  EXPECT_EQ(0U, leaked[0].referenced_count);
  EXPECT_EQ(0U, leaked[0].referenced_size);
}

TEST_F(LeakFoldingTest, two) {
  void* buffer1[1] = {nullptr};
  void* buffer2[1] = {nullptr};

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(2U, num_leaks);
  EXPECT_EQ(2 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(2U, leaked.size());
  EXPECT_EQ(0U, leaked[0].referenced_count);
  EXPECT_EQ(0U, leaked[0].referenced_size);
  EXPECT_EQ(0U, leaked[1].referenced_count);
  EXPECT_EQ(0U, leaked[1].referenced_size);
}

TEST_F(LeakFoldingTest, dominator) {
  void* buffer1[1];
  void* buffer2[1] = {nullptr};

  buffer1[0] = buffer2;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(2U, num_leaks);
  EXPECT_EQ(2 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(1U, leaked.size());
  EXPECT_EQ(1U, leaked[0].referenced_count);
  EXPECT_EQ(sizeof(uintptr_t), leaked[0].referenced_size);
}

TEST_F(LeakFoldingTest, cycle) {
  void* buffer1[1];
  void* buffer2[1];
  void* buffer3[1];

  buffer1[0] = buffer2;
  buffer2[0] = buffer3;
  buffer3[0] = buffer2;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);
  ALLOCATION(heap_walker, buffer3);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(3U, num_leaks);
  EXPECT_EQ(3 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(1U, leaked.size());
  EXPECT_EQ(2U, leaked[0].referenced_count);
  EXPECT_EQ(2 * sizeof(uintptr_t), leaked[0].referenced_size);
}

TEST_F(LeakFoldingTest, dominator_cycle) {
  void* buffer1[2] = {nullptr, nullptr};
  void* buffer2[2];
  void* buffer3[1] = {nullptr};

  buffer1[0] = &buffer2;
  buffer2[0] = &buffer1;
  buffer2[1] = &buffer3;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);
  ALLOCATION(heap_walker, buffer3);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(3U, num_leaks);
  EXPECT_EQ(5 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(2U, leaked.size());

  EXPECT_EQ(2U, leaked[0].referenced_count);
  EXPECT_EQ(3 * sizeof(uintptr_t), leaked[0].referenced_size);
  EXPECT_EQ(2U, leaked[1].referenced_count);
  EXPECT_EQ(3 * sizeof(uintptr_t), leaked[1].referenced_size);
}

TEST_F(LeakFoldingTest, two_cycles) {
  void* buffer1[1];
  void* buffer2[1];
  void* buffer3[1];
  void* buffer4[1];
  void* buffer5[1];
  void* buffer6[1];

  buffer1[0] = buffer3;
  buffer2[0] = buffer5;
  buffer3[0] = buffer4;
  buffer4[0] = buffer3;
  buffer5[0] = buffer6;
  buffer6[0] = buffer5;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);
  ALLOCATION(heap_walker, buffer3);
  ALLOCATION(heap_walker, buffer4);
  ALLOCATION(heap_walker, buffer5);
  ALLOCATION(heap_walker, buffer6);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(6U, num_leaks);
  EXPECT_EQ(6 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(2U, leaked.size());
  EXPECT_EQ(2U, leaked[0].referenced_count);
  EXPECT_EQ(2 * sizeof(uintptr_t), leaked[0].referenced_size);
  EXPECT_EQ(2U, leaked[1].referenced_count);
  EXPECT_EQ(2 * sizeof(uintptr_t), leaked[1].referenced_size);
}

TEST_F(LeakFoldingTest, two_dominator_cycles) {
  void* buffer1[1];
  void* buffer2[1];
  void* buffer3[1];
  void* buffer4[1];

  buffer1[0] = buffer2;
  buffer2[0] = buffer1;
  buffer3[0] = buffer4;
  buffer4[0] = buffer3;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);
  ALLOCATION(heap_walker, buffer3);
  ALLOCATION(heap_walker, buffer4);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(4U, num_leaks);
  EXPECT_EQ(4 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(4U, leaked.size());
  EXPECT_EQ(1U, leaked[0].referenced_count);
  EXPECT_EQ(sizeof(uintptr_t), leaked[0].referenced_size);
  EXPECT_EQ(1U, leaked[1].referenced_count);
  EXPECT_EQ(sizeof(uintptr_t), leaked[1].referenced_size);
  EXPECT_EQ(1U, leaked[2].referenced_count);
  EXPECT_EQ(sizeof(uintptr_t), leaked[2].referenced_size);
  EXPECT_EQ(1U, leaked[3].referenced_count);
  EXPECT_EQ(sizeof(uintptr_t), leaked[3].referenced_size);
}

TEST_F(LeakFoldingTest, giant_dominator_cycle) {
  const size_t n = 1000;
  void* buffer[n];

  HeapWalker heap_walker(heap_);

  for (size_t i = 0; i < n; i++) {
    ASSERT_TRUE(heap_walker.Allocation(reinterpret_cast<uintptr_t>(&buffer[i]),
                                       reinterpret_cast<uintptr_t>(&buffer[i + 1])));
  }

  for (size_t i = 0; i < n - 1; i++) {
    buffer[i] = &buffer[i + 1];
  }
  buffer[n - 1] = &buffer[0];

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(n, num_leaks);
  EXPECT_EQ(n * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(1000U, leaked.size());
  EXPECT_EQ(n - 1, leaked[0].referenced_count);
  EXPECT_EQ((n - 1) * sizeof(uintptr_t), leaked[0].referenced_size);
}

TEST_F(LeakFoldingTest, giant_cycle) {
  const size_t n = 1000;
  void* buffer[n];
  void* buffer1[1];

  HeapWalker heap_walker(heap_);

  for (size_t i = 0; i < n - 1; i++) {
    buffer[i] = &buffer[i + 1];
  }
  buffer[n - 1] = &buffer[0];

  buffer1[0] = &buffer[0];

  for (size_t i = 0; i < n; i++) {
    ASSERT_TRUE(heap_walker.Allocation(reinterpret_cast<uintptr_t>(&buffer[i]),
                                       reinterpret_cast<uintptr_t>(&buffer[i + 1])));
  }

  ALLOCATION(heap_walker, buffer1);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(n + 1, num_leaks);
  EXPECT_EQ((n + 1) * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(1U, leaked.size());
  EXPECT_EQ(n, leaked[0].referenced_count);
  EXPECT_EQ(n * sizeof(uintptr_t), leaked[0].referenced_size);
}

TEST_F(LeakFoldingTest, multipath) {
  void* buffer1[2];
  void* buffer2[1];
  void* buffer3[1];
  void* buffer4[1] = {nullptr};

  //    1
  //   / \
  //  v   v
  //  2   3
  //   \ /
  //    v
  //    4

  buffer1[0] = &buffer2;
  buffer1[1] = &buffer3;
  buffer2[0] = &buffer4;
  buffer3[0] = &buffer4;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);
  ALLOCATION(heap_walker, buffer3);
  ALLOCATION(heap_walker, buffer4);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(4U, num_leaks);
  EXPECT_EQ(5 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(1U, leaked.size());
  EXPECT_EQ(3U, leaked[0].referenced_count);
  EXPECT_EQ(3 * sizeof(uintptr_t), leaked[0].referenced_size);
}

TEST_F(LeakFoldingTest, multicycle) {
  void* buffer1[2]{};
  void* buffer2[2]{};
  void* buffer3[2]{};
  void* buffer4[2]{};

  //    1
  //   / ^
  //  v   \
  //  2 -> 3
  //   \   ^
  //    v /
  //     4

  buffer1[0] = &buffer2;
  buffer2[0] = &buffer3;
  buffer2[1] = &buffer4;
  buffer3[0] = &buffer1;
  buffer4[0] = &buffer3;

  HeapWalker heap_walker(heap_);

  ALLOCATION(heap_walker, buffer1);
  ALLOCATION(heap_walker, buffer2);
  ALLOCATION(heap_walker, buffer3);
  ALLOCATION(heap_walker, buffer4);

  LeakFolding folding(heap_, heap_walker);

  ASSERT_TRUE(folding.FoldLeaks());

  allocator::vector<LeakFolding::Leak> leaked(heap_);
  size_t num_leaks = 0;
  size_t leaked_bytes = 0;
  ASSERT_EQ(true, folding.Leaked(leaked, &num_leaks, &leaked_bytes));

  EXPECT_EQ(4U, num_leaks);
  EXPECT_EQ(8 * sizeof(uintptr_t), leaked_bytes);
  ASSERT_EQ(4U, leaked.size());
  EXPECT_EQ(3U, leaked[0].referenced_count);
  EXPECT_EQ(6 * sizeof(uintptr_t), leaked[0].referenced_size);
  EXPECT_EQ(3U, leaked[1].referenced_count);
  EXPECT_EQ(6 * sizeof(uintptr_t), leaked[1].referenced_size);
  EXPECT_EQ(3U, leaked[2].referenced_count);
  EXPECT_EQ(6 * sizeof(uintptr_t), leaked[2].referenced_size);
  EXPECT_EQ(3U, leaked[3].referenced_count);
  EXPECT_EQ(6 * sizeof(uintptr_t), leaked[3].referenced_size);
}

}  // namespace android
