/*
 * Copyright 2017, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <debuggerd/client.h>

#include <fcntl.h>
#include <stdio.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <chrono>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>

#include "util.h"

using namespace std::chrono_literals;
using android::base::unique_fd;

static int getThreadCount() {
  int threadCount = 1024;
  std::vector<std::string> characteristics =
      android::base::Split(android::base::GetProperty("ro.build.characteristics", ""), ",");
  if (std::find(characteristics.begin(), characteristics.end(), "embedded")
      != characteristics.end()) {
    // 128 is the realistic number for iot devices.
    threadCount = 128;
  }
  return threadCount;
}

TEST(debuggerd_client, race) {
  static int THREAD_COUNT = getThreadCount();

  // Semaphore incremented once per thread started.
  unique_fd barrier(eventfd(0, EFD_SEMAPHORE));
  ASSERT_NE(-1, barrier.get());

  pid_t forkpid = fork();
  ASSERT_NE(-1, forkpid);
  if (forkpid == 0) {
    // Spawn a bunch of threads, to make crash_dump take longer.
    std::vector<std::thread> threads;
    threads.reserve(THREAD_COUNT);
    for (int i = 0; i < THREAD_COUNT; ++i) {
      threads.emplace_back([&barrier]() {
        uint64_t count = 1;
        ASSERT_NE(-1, write(barrier.get(), &count, sizeof(count)));
        for (;;) {
          pause();
        }
      });
    }
    for (;;) {
      pause();
    }
  }

  // Wait for the child to spawn all of its threads.
  for (int i = 0; i < THREAD_COUNT; ++i) {
    uint64_t count;
    ASSERT_NE(-1, read(barrier.get(), &count, sizeof(count)));
  }

  unique_fd pipe_read, pipe_write;
  ASSERT_TRUE(Pipe(&pipe_read, &pipe_write));

  // 16 MiB should be enough for everyone.
  constexpr int PIPE_SIZE = 16 * 1024 * 1024;
  ASSERT_EQ(PIPE_SIZE, fcntl(pipe_read.get(), F_SETPIPE_SZ, PIPE_SIZE));

  ASSERT_TRUE(
      debuggerd_trigger_dump(forkpid, kDebuggerdNativeBacktrace, 60000, std::move(pipe_write)));
  // Immediately kill the forked child, to make sure that the dump didn't return early.
  ASSERT_EQ(0, kill(forkpid, SIGKILL)) << strerror(errno);

  // Check the output.
  std::string result;
  ASSERT_TRUE(android::base::ReadFdToString(pipe_read.get(), &result));

  // Look for "----- end <PID> -----"
  int found_end = 0;

  std::string expected_end = android::base::StringPrintf("----- end %d -----", forkpid);

  std::vector<std::string> lines = android::base::Split(result, "\n");
  for (const std::string& line : lines) {
    if (line == expected_end) {
      ++found_end;
    }
  }

  EXPECT_EQ(1, found_end) << "\nOutput: \n" << result;
}

TEST(debuggerd_client, no_timeout) {
  unique_fd pipe_read, pipe_write;
  ASSERT_TRUE(Pipe(&pipe_read, &pipe_write));

  pid_t forkpid = fork();
  ASSERT_NE(-1, forkpid);
  if (forkpid == 0) {
    pipe_write.reset();
    char dummy;
    TEMP_FAILURE_RETRY(read(pipe_read.get(), &dummy, sizeof(dummy)));
    exit(0);
  }

  pipe_read.reset();

  unique_fd output_read, output_write;
  ASSERT_TRUE(Pipe(&output_read, &output_write));
  ASSERT_TRUE(
      debuggerd_trigger_dump(forkpid, kDebuggerdNativeBacktrace, 0, std::move(output_write)));
}
