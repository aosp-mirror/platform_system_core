/*
 * Copyright (C) 2013 The Android Open Source Project
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

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <backtrace/Backtrace.h>
#include <UniquePtr.h>

#include <cutils/atomic.h>
#include <gtest/gtest.h>

#include <vector>

#include "thread_utils.h"

// Number of microseconds per milliseconds.
#define US_PER_MSEC             1000

// Number of nanoseconds in a second.
#define NS_PER_SEC              1000000000ULL

// Number of simultaneous dumping operations to perform.
#define NUM_THREADS  20

// Number of simultaneous threads running in our forked process.
#define NUM_PTRACE_THREADS 5

typedef struct {
  pid_t tid;
  int32_t state;
  pthread_t threadId;
} thread_t;

typedef struct {
  thread_t thread;
  Backtrace* backtrace;
  int32_t* now;
  int32_t done;
} dump_thread_t;

extern "C" {
// Prototypes for functions in the test library.
int test_level_one(int, int, int, int, void (*)(void*), void*);

int test_recursive_call(int, void (*)(void*), void*);
}

uint64_t NanoTime() {
  struct timespec t = { 0, 0 };
  clock_gettime(CLOCK_MONOTONIC, &t);
  return static_cast<uint64_t>(t.tv_sec * NS_PER_SEC + t.tv_nsec);
}

void DumpFrames(Backtrace* backtrace) {
  if (backtrace->NumFrames() == 0) {
    printf("    No frames to dump\n");
    return;
  }

  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    printf("    %s\n", backtrace->FormatFrameData(i).c_str());
  }
}

void WaitForStop(pid_t pid) {
  uint64_t start = NanoTime();

  siginfo_t si;
  while (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) < 0 && (errno == EINTR || errno == ESRCH)) {
    if ((NanoTime() - start) > NS_PER_SEC) {
      printf("The process did not get to a stopping point in 1 second.\n");
      break;
    }
    usleep(US_PER_MSEC);
  }
}

bool ReadyLevelBacktrace(Backtrace* backtrace) {
  // See if test_level_four is in the backtrace.
  bool found = false;
  for (size_t i = 0; i < backtrace->NumFrames(); i++) {
    const backtrace_frame_data_t* frame = backtrace->GetFrame(i);
    if (frame->func_name != NULL && strcmp(frame->func_name, "test_level_four") == 0) {
      found = true;
      break;
    }
  }

  return found;
}

void VerifyLevelDump(Backtrace* backtrace) {
  ASSERT_GT(backtrace->NumFrames(), static_cast<size_t>(0));
  ASSERT_LT(backtrace->NumFrames(), static_cast<size_t>(MAX_BACKTRACE_FRAMES));

  // Look through the frames starting at the highest to find the
  // frame we want.
  size_t frame_num = 0;
  for (size_t i = backtrace->NumFrames()-1; i > 2; i--) {
    if (backtrace->GetFrame(i)->func_name != NULL &&
        strcmp(backtrace->GetFrame(i)->func_name, "test_level_one") == 0) {
      frame_num = i;
      break;
    }
  }
  ASSERT_LT(static_cast<size_t>(0), frame_num);
  ASSERT_LE(static_cast<size_t>(3), frame_num);

  ASSERT_TRUE(NULL != backtrace->GetFrame(frame_num)->func_name);
  ASSERT_STREQ(backtrace->GetFrame(frame_num)->func_name, "test_level_one");
  ASSERT_TRUE(NULL != backtrace->GetFrame(frame_num-1)->func_name);
  ASSERT_STREQ(backtrace->GetFrame(frame_num-1)->func_name, "test_level_two");
  ASSERT_TRUE(NULL != backtrace->GetFrame(frame_num-2)->func_name);
  ASSERT_STREQ(backtrace->GetFrame(frame_num-2)->func_name, "test_level_three");
  ASSERT_TRUE(NULL != backtrace->GetFrame(frame_num-3)->func_name);
  ASSERT_STREQ(backtrace->GetFrame(frame_num-3)->func_name, "test_level_four");
}

void VerifyLevelBacktrace(void*) {
  UniquePtr<Backtrace> backtrace(
      Backtrace::Create(BACKTRACE_CURRENT_PROCESS, BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyLevelDump(backtrace.get());
}

bool ReadyMaxBacktrace(Backtrace* backtrace) {
  return (backtrace->NumFrames() == MAX_BACKTRACE_FRAMES);
}

void VerifyMaxDump(Backtrace* backtrace) {
  ASSERT_EQ(backtrace->NumFrames(), static_cast<size_t>(MAX_BACKTRACE_FRAMES));
  // Verify that the last frame is our recursive call.
  ASSERT_TRUE(NULL != backtrace->GetFrame(MAX_BACKTRACE_FRAMES-1)->func_name);
  ASSERT_STREQ(backtrace->GetFrame(MAX_BACKTRACE_FRAMES-1)->func_name,
               "test_recursive_call");
}

void VerifyMaxBacktrace(void*) {
  UniquePtr<Backtrace> backtrace(
      Backtrace::Create(BACKTRACE_CURRENT_PROCESS, BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyMaxDump(backtrace.get());
}

void ThreadSetState(void* data) {
  thread_t* thread = reinterpret_cast<thread_t*>(data);
  android_atomic_acquire_store(1, &thread->state);
  volatile int i = 0;
  while (thread->state) {
    i++;
  }
}

void VerifyThreadTest(pid_t tid, void (*VerifyFunc)(Backtrace*)) {
  UniquePtr<Backtrace> backtrace(Backtrace::Create(getpid(), tid));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyFunc(backtrace.get());
}

bool WaitForNonZero(int32_t* value, uint64_t seconds) {
  uint64_t start = NanoTime();
  do {
    if (android_atomic_acquire_load(value)) {
      return true;
    }
  } while ((NanoTime() - start) < seconds * NS_PER_SEC);
  return false;
}

TEST(libbacktrace, local_trace) {
  ASSERT_NE(test_level_one(1, 2, 3, 4, VerifyLevelBacktrace, NULL), 0);
}

void VerifyIgnoreFrames(
    Backtrace* bt_all, Backtrace* bt_ign1,
    Backtrace* bt_ign2, const char* cur_proc) {
  EXPECT_EQ(bt_all->NumFrames(), bt_ign1->NumFrames() + 1);
  EXPECT_EQ(bt_all->NumFrames(), bt_ign2->NumFrames() + 2);

  // Check all of the frames are the same > the current frame.
  bool check = (cur_proc == NULL);
  for (size_t i = 0; i < bt_ign2->NumFrames(); i++) {
    if (check) {
      EXPECT_EQ(bt_ign2->GetFrame(i)->pc, bt_ign1->GetFrame(i+1)->pc);
      EXPECT_EQ(bt_ign2->GetFrame(i)->sp, bt_ign1->GetFrame(i+1)->sp);
      EXPECT_EQ(bt_ign2->GetFrame(i)->stack_size, bt_ign1->GetFrame(i+1)->stack_size);

      EXPECT_EQ(bt_ign2->GetFrame(i)->pc, bt_all->GetFrame(i+2)->pc);
      EXPECT_EQ(bt_ign2->GetFrame(i)->sp, bt_all->GetFrame(i+2)->sp);
      EXPECT_EQ(bt_ign2->GetFrame(i)->stack_size, bt_all->GetFrame(i+2)->stack_size);
    }
    if (!check && bt_ign2->GetFrame(i)->func_name &&
        strcmp(bt_ign2->GetFrame(i)->func_name, cur_proc) == 0) {
      check = true;
    }
  }
}

void VerifyLevelIgnoreFrames(void*) {
  UniquePtr<Backtrace> all(
      Backtrace::Create(BACKTRACE_CURRENT_PROCESS, BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(all.get() != NULL);
  ASSERT_TRUE(all->Unwind(0));

  UniquePtr<Backtrace> ign1(
      Backtrace::Create(BACKTRACE_CURRENT_PROCESS, BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(ign1.get() != NULL);
  ASSERT_TRUE(ign1->Unwind(1));

  UniquePtr<Backtrace> ign2(
      Backtrace::Create(BACKTRACE_CURRENT_PROCESS, BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(ign2.get() != NULL);
  ASSERT_TRUE(ign2->Unwind(2));

  VerifyIgnoreFrames(all.get(), ign1.get(), ign2.get(), "VerifyLevelIgnoreFrames");
}

TEST(libbacktrace, local_trace_ignore_frames) {
  ASSERT_NE(test_level_one(1, 2, 3, 4, VerifyLevelIgnoreFrames, NULL), 0);
}

TEST(libbacktrace, local_max_trace) {
  ASSERT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, VerifyMaxBacktrace, NULL), 0);
}

void VerifyProcTest(pid_t pid, pid_t tid,
                    bool (*ReadyFunc)(Backtrace*),
                    void (*VerifyFunc)(Backtrace*)) {
  pid_t ptrace_tid;
  if (tid < 0) {
    ptrace_tid = pid;
  } else {
    ptrace_tid = tid;
  }
  uint64_t start = NanoTime();
  bool verified = false;
  do {
    usleep(US_PER_MSEC);
    if (ptrace(PTRACE_ATTACH, ptrace_tid, 0, 0) == 0) {
      // Wait for the process to get to a stopping point.
      WaitForStop(ptrace_tid);

      UniquePtr<Backtrace> backtrace(Backtrace::Create(pid, tid));
      ASSERT_TRUE(backtrace->Unwind(0));
      ASSERT_TRUE(backtrace.get() != NULL);
      if (ReadyFunc(backtrace.get())) {
        VerifyFunc(backtrace.get());
        verified = true;
      }

      ASSERT_TRUE(ptrace(PTRACE_DETACH, ptrace_tid, 0, 0) == 0);
    }
    // If 5 seconds have passed, then we are done.
  } while (!verified && (NanoTime() - start) <= 5 * NS_PER_SEC);
  ASSERT_TRUE(verified);
}

TEST(libbacktrace, ptrace_trace) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    ASSERT_NE(test_level_one(1, 2, 3, 4, NULL, NULL), 0);
    exit(1);
  }
  VerifyProcTest(pid, BACKTRACE_CURRENT_THREAD, ReadyLevelBacktrace, VerifyLevelDump);

  kill(pid, SIGKILL);
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

TEST(libbacktrace, ptrace_max_trace) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    ASSERT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, NULL, NULL), 0);
    exit(1);
  }
  VerifyProcTest(pid, BACKTRACE_CURRENT_THREAD, ReadyMaxBacktrace, VerifyMaxDump);

  kill(pid, SIGKILL);
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

void VerifyProcessIgnoreFrames(Backtrace* bt_all) {
  UniquePtr<Backtrace> ign1(Backtrace::Create(bt_all->Pid(), BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(ign1.get() != NULL);
  ASSERT_TRUE(ign1->Unwind(1));

  UniquePtr<Backtrace> ign2(Backtrace::Create(bt_all->Pid(), BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(ign2.get() != NULL);
  ASSERT_TRUE(ign2->Unwind(2));

  VerifyIgnoreFrames(bt_all, ign1.get(), ign2.get(), NULL);
}

TEST(libbacktrace, ptrace_ignore_frames) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    ASSERT_NE(test_level_one(1, 2, 3, 4, NULL, NULL), 0);
    exit(1);
  }
  VerifyProcTest(pid, BACKTRACE_CURRENT_THREAD, ReadyLevelBacktrace, VerifyProcessIgnoreFrames);

  kill(pid, SIGKILL);
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

// Create a process with multiple threads and dump all of the threads.
void* PtraceThreadLevelRun(void*) {
  EXPECT_NE(test_level_one(1, 2, 3, 4, NULL, NULL), 0);
  return NULL;
}

void GetThreads(pid_t pid, std::vector<pid_t>* threads) {
  // Get the list of tasks.
  char task_path[128];
  snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

  DIR* tasks_dir = opendir(task_path);
  ASSERT_TRUE(tasks_dir != NULL);
  struct dirent* entry;
  while ((entry = readdir(tasks_dir)) != NULL) {
    char* end;
    pid_t tid = strtoul(entry->d_name, &end, 10);
    if (*end == '\0') {
      threads->push_back(tid);
    }
  }
  closedir(tasks_dir);
}

TEST(libbacktrace, ptrace_threads) {
  pid_t pid;
  if ((pid = fork()) == 0) {
    for (size_t i = 0; i < NUM_PTRACE_THREADS; i++) {
      pthread_attr_t attr;
      pthread_attr_init(&attr);
      pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

      pthread_t thread;
      ASSERT_TRUE(pthread_create(&thread, &attr, PtraceThreadLevelRun, NULL) == 0);
    }
    ASSERT_NE(test_level_one(1, 2, 3, 4, NULL, NULL), 0);
    exit(1);
  }

  // Check to see that all of the threads are running before unwinding.
  std::vector<pid_t> threads;
  uint64_t start = NanoTime();
  do {
    usleep(US_PER_MSEC);
    threads.clear();
    GetThreads(pid, &threads);
  } while ((threads.size() != NUM_PTRACE_THREADS + 1) &&
      ((NanoTime() - start) <= 5 * NS_PER_SEC));
  ASSERT_EQ(threads.size(), static_cast<size_t>(NUM_PTRACE_THREADS + 1));

  ASSERT_TRUE(ptrace(PTRACE_ATTACH, pid, 0, 0) == 0);
  WaitForStop(pid);
  for (std::vector<int>::const_iterator it = threads.begin(); it != threads.end(); ++it) {
    // Skip the current forked process, we only care about the threads.
    if (pid == *it) {
      continue;
    }
    VerifyProcTest(pid, *it, ReadyLevelBacktrace, VerifyLevelDump);
  }
  ASSERT_TRUE(ptrace(PTRACE_DETACH, pid, 0, 0) == 0);

  kill(pid, SIGKILL);
  int status;
  ASSERT_EQ(waitpid(pid, &status, 0), pid);
}

void VerifyLevelThread(void*) {
  UniquePtr<Backtrace> backtrace(Backtrace::Create(getpid(), gettid()));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyLevelDump(backtrace.get());
}

TEST(libbacktrace, thread_current_level) {
  ASSERT_NE(test_level_one(1, 2, 3, 4, VerifyLevelThread, NULL), 0);
}

void VerifyMaxThread(void*) {
  UniquePtr<Backtrace> backtrace(Backtrace::Create(getpid(), gettid()));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyMaxDump(backtrace.get());
}

TEST(libbacktrace, thread_current_max) {
  ASSERT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, VerifyMaxThread, NULL), 0);
}

void* ThreadLevelRun(void* data) {
  thread_t* thread = reinterpret_cast<thread_t*>(data);

  thread->tid = gettid();
  EXPECT_NE(test_level_one(1, 2, 3, 4, ThreadSetState, data), 0);
  return NULL;
}

TEST(libbacktrace, thread_level_trace) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  thread_t thread_data = { 0, 0, 0 };
  pthread_t thread;
  ASSERT_TRUE(pthread_create(&thread, &attr, ThreadLevelRun, &thread_data) == 0);

  // Wait up to 2 seconds for the tid to be set.
  ASSERT_TRUE(WaitForNonZero(&thread_data.state, 2));

  // Save the current signal action and make sure it is restored afterwards.
  struct sigaction cur_action;
  ASSERT_TRUE(sigaction(SIGURG, NULL, &cur_action) == 0);

  UniquePtr<Backtrace> backtrace(Backtrace::Create(getpid(), thread_data.tid));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyLevelDump(backtrace.get());

  // Tell the thread to exit its infinite loop.
  android_atomic_acquire_store(0, &thread_data.state);

  // Verify that the old action was restored.
  struct sigaction new_action;
  ASSERT_TRUE(sigaction(SIGURG, NULL, &new_action) == 0);
  EXPECT_EQ(cur_action.sa_sigaction, new_action.sa_sigaction);
  EXPECT_EQ(cur_action.sa_flags, new_action.sa_flags);
}

TEST(libbacktrace, thread_ignore_frames) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  thread_t thread_data = { 0, 0, 0 };
  pthread_t thread;
  ASSERT_TRUE(pthread_create(&thread, &attr, ThreadLevelRun, &thread_data) == 0);

  // Wait up to 2 seconds for the tid to be set.
  ASSERT_TRUE(WaitForNonZero(&thread_data.state, 2));

  UniquePtr<Backtrace> all(Backtrace::Create(getpid(), thread_data.tid));
  ASSERT_TRUE(all.get() != NULL);
  ASSERT_TRUE(all->Unwind(0));

  UniquePtr<Backtrace> ign1(Backtrace::Create(getpid(), thread_data.tid));
  ASSERT_TRUE(ign1.get() != NULL);
  ASSERT_TRUE(ign1->Unwind(1));

  UniquePtr<Backtrace> ign2(Backtrace::Create(getpid(), thread_data.tid));
  ASSERT_TRUE(ign2.get() != NULL);
  ASSERT_TRUE(ign2->Unwind(2));

  VerifyIgnoreFrames(all.get(), ign1.get(), ign2.get(), NULL);

  // Tell the thread to exit its infinite loop.
  android_atomic_acquire_store(0, &thread_data.state);
}

void* ThreadMaxRun(void* data) {
  thread_t* thread = reinterpret_cast<thread_t*>(data);

  thread->tid = gettid();
  EXPECT_NE(test_recursive_call(MAX_BACKTRACE_FRAMES+10, ThreadSetState, data), 0);
  return NULL;
}

TEST(libbacktrace, thread_max_trace) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

  thread_t thread_data = { 0, 0, 0 };
  pthread_t thread;
  ASSERT_TRUE(pthread_create(&thread, &attr, ThreadMaxRun, &thread_data) == 0);

  // Wait for the tid to be set.
  ASSERT_TRUE(WaitForNonZero(&thread_data.state, 2));

  UniquePtr<Backtrace> backtrace(Backtrace::Create(getpid(), thread_data.tid));
  ASSERT_TRUE(backtrace.get() != NULL);
  ASSERT_TRUE(backtrace->Unwind(0));

  VerifyMaxDump(backtrace.get());

  // Tell the thread to exit its infinite loop.
  android_atomic_acquire_store(0, &thread_data.state);
}

void* ThreadDump(void* data) {
  dump_thread_t* dump = reinterpret_cast<dump_thread_t*>(data);
  while (true) {
    if (android_atomic_acquire_load(dump->now)) {
      break;
    }
  }

  // The status of the actual unwind will be checked elsewhere.
  dump->backtrace = Backtrace::Create(getpid(), dump->thread.tid);
  dump->backtrace->Unwind(0);

  android_atomic_acquire_store(1, &dump->done);

  return NULL;
}

TEST(libbacktrace, thread_multiple_dump) {
  // Dump NUM_THREADS simultaneously.
  std::vector<thread_t> runners(NUM_THREADS);
  std::vector<dump_thread_t> dumpers(NUM_THREADS);

  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
  for (size_t i = 0; i < NUM_THREADS; i++) {
    // Launch the runners, they will spin in hard loops doing nothing.
    runners[i].tid = 0;
    runners[i].state = 0;
    ASSERT_TRUE(pthread_create(&runners[i].threadId, &attr, ThreadMaxRun, &runners[i]) == 0);
  }

  // Wait for tids to be set.
  for (std::vector<thread_t>::iterator it = runners.begin(); it != runners.end(); ++it) {
    ASSERT_TRUE(WaitForNonZero(&it->state, 10));
  }

  // Start all of the dumpers at once, they will spin until they are signalled
  // to begin their dump run.
  int32_t dump_now = 0;
  for (size_t i = 0; i < NUM_THREADS; i++) {
    dumpers[i].thread.tid = runners[i].tid;
    dumpers[i].thread.state = 0;
    dumpers[i].done = 0;
    dumpers[i].now = &dump_now;

    ASSERT_TRUE(pthread_create(&dumpers[i].thread.threadId, &attr, ThreadDump, &dumpers[i]) == 0);
  }

  // Start all of the dumpers going at once.
  android_atomic_acquire_store(1, &dump_now);

  for (size_t i = 0; i < NUM_THREADS; i++) {
    ASSERT_TRUE(WaitForNonZero(&dumpers[i].done, 10));

    // Tell the runner thread to exit its infinite loop.
    android_atomic_acquire_store(0, &runners[i].state);

    ASSERT_TRUE(dumpers[i].backtrace != NULL);
    VerifyMaxDump(dumpers[i].backtrace);

    delete dumpers[i].backtrace;
    dumpers[i].backtrace = NULL;
  }
}

TEST(libbacktrace, format_test) {
  UniquePtr<Backtrace> backtrace(Backtrace::Create(getpid(), BACKTRACE_CURRENT_THREAD));
  ASSERT_TRUE(backtrace.get() != NULL);

  backtrace_frame_data_t frame;
  memset(&frame, 0, sizeof(backtrace_frame_data_t));

  frame.num = 1;
#if defined(__LP64__)
  EXPECT_STREQ("#01 pc 0000000000000000  <unknown>",
#else
  EXPECT_STREQ("#01 pc 00000000  <unknown>",
#endif
               backtrace->FormatFrameData(&frame).c_str());

  frame.pc = 0x12345678;
  frame.map_name = "MapFake";
#if defined(__LP64__)
  EXPECT_STREQ("#01 pc 0000000012345678  MapFake",
#else
  EXPECT_STREQ("#01 pc 12345678  MapFake",
#endif
               backtrace->FormatFrameData(&frame).c_str());

  frame.func_name = const_cast<char*>("ProcFake");
#if defined(__LP64__)
  EXPECT_STREQ("#01 pc 0000000012345678  MapFake (ProcFake)",
#else
  EXPECT_STREQ("#01 pc 12345678  MapFake (ProcFake)",
#endif
               backtrace->FormatFrameData(&frame).c_str());

  frame.func_offset = 645;
#if defined(__LP64__)
  EXPECT_STREQ("#01 pc 0000000012345678  MapFake (ProcFake+645)",
#else
  EXPECT_STREQ("#01 pc 12345678  MapFake (ProcFake+645)",
#endif
               backtrace->FormatFrameData(&frame).c_str());
}
