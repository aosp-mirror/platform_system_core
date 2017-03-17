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

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <vector>

#include <android-base/test_utils.h>
#include <android-base/file.h>
#include <gtest/gtest.h>

#include "Memory.h"

class MemoryRemoteTest : public ::testing::Test {
 protected:
  static uint64_t NanoTime() {
    struct timespec t = { 0, 0 };
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec * NS_PER_SEC + t.tv_nsec);
  }

  static bool Attach(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1) {
      return false;
    }

    uint64_t start = NanoTime();
    siginfo_t si;
    while (TEMP_FAILURE_RETRY(ptrace(PTRACE_GETSIGINFO, pid, 0, &si)) < 0 && errno == ESRCH) {
      if ((NanoTime() - start) > 10 * NS_PER_SEC) {
        printf("%d: Failed to stop after 10 seconds.\n", pid);
        return false;
      }
      usleep(30);
    }
    return true;
  }

  static bool Detach(pid_t pid) {
    return ptrace(PTRACE_DETACH, pid, 0, 0) == 0;
  }

  static constexpr size_t NS_PER_SEC = 1000000000ULL;
};

TEST_F(MemoryRemoteTest, read) {
  std::vector<uint8_t> src(1024);
  memset(src.data(), 0x4c, 1024);

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(Attach(pid));

  MemoryRemote remote(pid);

  std::vector<uint8_t> dst(1024);
  ASSERT_TRUE(remote.Read(reinterpret_cast<uint64_t>(src.data()), dst.data(), 1024));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }

  ASSERT_TRUE(Detach(pid));

  kill(pid, SIGKILL);
}

TEST_F(MemoryRemoteTest, read_fail) {
  int pagesize = getpagesize();
  void* src = mmap(nullptr, pagesize * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE,-1, 0);
  memset(src, 0x4c, pagesize * 2);
  ASSERT_NE(MAP_FAILED, src);
  // Put a hole right after the first page.
  ASSERT_EQ(0, munmap(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(src) + pagesize),
                      pagesize));

  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(Attach(pid));

  MemoryRemote remote(pid);

  std::vector<uint8_t> dst(pagesize);
  ASSERT_TRUE(remote.Read(reinterpret_cast<uint64_t>(src), dst.data(), pagesize));
  for (size_t i = 0; i < 1024; i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }

  ASSERT_FALSE(remote.Read(reinterpret_cast<uint64_t>(src) + pagesize, dst.data(), 1));
  ASSERT_TRUE(remote.Read(reinterpret_cast<uint64_t>(src) + pagesize - 1, dst.data(), 1));
  ASSERT_FALSE(remote.Read(reinterpret_cast<uint64_t>(src) + pagesize - 4, dst.data(), 8));

  ASSERT_EQ(0, munmap(src, pagesize));

  ASSERT_TRUE(Detach(pid));

  kill(pid, SIGKILL);
}

TEST_F(MemoryRemoteTest, read_illegal) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    while (true);
    exit(1);
  }
  ASSERT_LT(0, pid);

  ASSERT_TRUE(Attach(pid));

  MemoryRemote remote(pid);

  std::vector<uint8_t> dst(100);
  ASSERT_FALSE(remote.Read(0, dst.data(), 1));
  ASSERT_FALSE(remote.Read(0, dst.data(), 100));

  ASSERT_TRUE(Detach(pid));

  kill(pid, SIGKILL);
}
