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

#include <fcntl.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <memunreachable/memunreachable.h>

#include "bionic.h"

namespace android {

class HiddenPointer {
 public:
  // Since we're doing such a good job of hiding it, the static analyzer
  // thinks that we're leaking this `malloc`. This is probably related to
  // https://bugs.llvm.org/show_bug.cgi?id=34198. NOLINTNEXTLINE
  explicit HiddenPointer(size_t size = 256) { Set(malloc(size)); }
  ~HiddenPointer() { Free(); }
  void* Get() { return reinterpret_cast<void*>(~ptr_); }
  void Free() {
    free(Get());
    Set(nullptr);
  }

 private:
  void Set(void* ptr) { ptr_ = ~reinterpret_cast<uintptr_t>(ptr); }
  volatile uintptr_t ptr_;
};

// Trick the compiler into thinking a value on the stack is still referenced.
static void Ref(void** ptr) {
  write(0, ptr, 0);
}

class MemunreachableTest : public ::testing::Test {
 protected:
  virtual void SetUp() {
    CleanStack(8192);
    CleanTcache();
  }

  virtual void TearDown() {
    CleanStack(8192);
    CleanTcache();
  }

  // Allocate a buffer on the stack and zero it to make sure there are no
  // stray pointers from old test runs.
  void __attribute__((noinline)) CleanStack(size_t size) {
    void* buf = alloca(size);
    memset(buf, 0, size);
    Ref(&buf);
  }

  // Disable and re-enable malloc to flush the jemalloc tcache to make sure
  // there are stray pointers from old test runs there.
  void CleanTcache() {
    malloc_disable();
    malloc_enable();
  }
};

TEST_F(MemunreachableTest, clean) {
  UnreachableMemoryInfo info;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  ASSERT_TRUE(GetUnreachableMemory(info));
  ASSERT_EQ(0U, info.leaks.size());
}

TEST_F(MemunreachableTest, stack) {
  HiddenPointer hidden_ptr;

  {
    void* ptr = hidden_ptr.Get();
    Ref(&ptr);

    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());

    ptr = nullptr;
  }

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size());
  }

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }
}

void* g_ptr;

TEST_F(MemunreachableTest, global) {
  HiddenPointer hidden_ptr;

  g_ptr = hidden_ptr.Get();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }

  g_ptr = nullptr;

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size());
  }

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }
}

TEST_F(MemunreachableTest, tls) {
  HiddenPointer hidden_ptr;
  pthread_key_t key;
  pthread_key_create(&key, nullptr);

  pthread_setspecific(key, hidden_ptr.Get());

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }

  pthread_setspecific(key, nullptr);

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size());
  }

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }

  pthread_key_delete(key);
}

TEST_F(MemunreachableTest, twice) {
  HiddenPointer hidden_ptr;

  {
    void* ptr = hidden_ptr.Get();
    Ref(&ptr);

    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());

    ptr = nullptr;
  }

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size());
  }

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(1U, info.leaks.size());
  }

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }
}

TEST_F(MemunreachableTest, log) {
  HiddenPointer hidden_ptr;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }
}

TEST_F(MemunreachableTest, notdumpable) {
  if (getuid() == 0) {
    // TODO(ccross): make this a skipped test when gtest supports them
    printf("[ SKIP     ] Not testable when running as root\n");
    return;
  }

  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 0));

  HiddenPointer hidden_ptr;

  EXPECT_FALSE(LogUnreachableMemory(true, 100));

  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 1));
}

TEST_F(MemunreachableTest, leak_lots) {
  std::vector<HiddenPointer> hidden_ptrs;
  hidden_ptrs.resize(1024);

  ASSERT_TRUE(LogUnreachableMemory(true, 100));
}

}  // namespace android
