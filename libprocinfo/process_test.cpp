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

#include <procinfo/process.h>

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include <set>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <android-base/stringprintf.h>

#if !defined(__BIONIC__)
#include <syscall.h>
static pid_t gettid() {
  return syscall(__NR_gettid);
}
#endif

TEST(process_info, process_info_smoke) {
  android::procinfo::ProcessInfo self;
  ASSERT_TRUE(android::procinfo::GetProcessInfo(gettid(), &self));
  ASSERT_EQ(gettid(), self.tid);
  ASSERT_EQ(getpid(), self.pid);
  ASSERT_EQ(getppid(), self.ppid);
  ASSERT_EQ(getuid(), self.uid);
  ASSERT_EQ(getgid(), self.gid);
}

TEST(process_info, process_info_proc_pid_fd_smoke) {
  android::procinfo::ProcessInfo self;
  int fd = open(android::base::StringPrintf("/proc/%d", gettid()).c_str(), O_DIRECTORY | O_RDONLY);
  ASSERT_NE(-1, fd);
  ASSERT_TRUE(android::procinfo::GetProcessInfoFromProcPidFd(fd, &self));

  // Process name is capped at 15 bytes.
  ASSERT_EQ("libprocinfo_tes", self.name);
  ASSERT_EQ(gettid(), self.tid);
  ASSERT_EQ(getpid(), self.pid);
  ASSERT_EQ(getppid(), self.ppid);
  ASSERT_EQ(getuid(), self.uid);
  ASSERT_EQ(getgid(), self.gid);
  close(fd);
}

TEST(process_info, process_tids_smoke) {
  pid_t main_tid = gettid();
  std::thread([main_tid]() {
    pid_t thread_tid = gettid();

    {
      std::vector<pid_t> vec;
      ASSERT_TRUE(android::procinfo::GetProcessTids(getpid(), &vec));
      ASSERT_EQ(1, std::count(vec.begin(), vec.end(), main_tid));
      ASSERT_EQ(1, std::count(vec.begin(), vec.end(), thread_tid));
    }

    {
      std::set<pid_t> set;
      ASSERT_TRUE(android::procinfo::GetProcessTids(getpid(), &set));
      ASSERT_EQ(1, std::count(set.begin(), set.end(), main_tid));
      ASSERT_EQ(1, std::count(set.begin(), set.end(), thread_tid));
    }
  }).join();
}
