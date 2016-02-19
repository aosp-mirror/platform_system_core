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
#include <unistd.h>
#include <sys/prctl.h>

#include <gtest/gtest.h>

#include <memunreachable/memunreachable.h>

void* ptr;

class HiddenPointer {
 public:
  HiddenPointer(size_t size = 256) {
    Set(malloc(size));
  }
  ~HiddenPointer() {
    Free();
  }
  void* Get() {
    return reinterpret_cast<void*>(~ptr_);
  }
  void Free() {
    free(Get());
    Set(nullptr);
  }
 private:
  void Set(void* ptr) {
    ptr_ = ~reinterpret_cast<uintptr_t>(ptr);
  }
  volatile uintptr_t ptr_;
};

static void Ref(void* ptr) {
  write(0, ptr, 0);
}

TEST(MemunreachableTest, clean) {
  UnreachableMemoryInfo info;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  ASSERT_TRUE(GetUnreachableMemory(info));
  ASSERT_EQ(0U, info.leaks.size());
}

TEST(MemunreachableTest, stack) {
  HiddenPointer hidden_ptr;

  {
    void* ptr = hidden_ptr.Get();
    Ref(ptr);

    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());

    Ref(ptr);
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

TEST(MemunreachableTest, global) {
  HiddenPointer hidden_ptr;

  ptr = hidden_ptr.Get();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }

  ptr = NULL;

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

TEST(MemunreachableTest, tls) {
  HiddenPointer hidden_ptr;
  pthread_key_t key;
  pthread_key_create(&key, NULL);

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

TEST(MemunreachableTest, twice) {
  HiddenPointer hidden_ptr;

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

TEST(MemunreachableTest, log) {
  HiddenPointer hidden_ptr;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  hidden_ptr.Free();

  {
    UnreachableMemoryInfo info;

    ASSERT_TRUE(GetUnreachableMemory(info));
    ASSERT_EQ(0U, info.leaks.size());
  }
}

TEST(MemunreachableTest, notdumpable) {
  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 0));

  HiddenPointer hidden_ptr;

  ASSERT_TRUE(LogUnreachableMemory(true, 100));

  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 1));
}

TEST(MemunreachableTest, leak_lots) {
  std::vector<HiddenPointer> hidden_ptrs;
  hidden_ptrs.resize(1024);

  ASSERT_TRUE(LogUnreachableMemory(true, 100));
}
