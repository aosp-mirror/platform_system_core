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

#include "ThreadCapture.h"

#include <fcntl.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <thread>

#include <gtest/gtest.h>

#include "Allocator.h"
#include "ScopedDisableMalloc.h"
#include "ScopedPipe.h"

using namespace std::chrono_literals;

namespace android {

class ThreadListTest : public ::testing::TestWithParam<int> {
 public:
  ThreadListTest() : stop_(false) {}

  ~ThreadListTest() {
    // pthread_join may return before the entry in /proc/pid/task/ is gone,
    // loop until ListThreads only finds the main thread so the next test
    // doesn't fail.
    WaitForThreads();
  }

  virtual void TearDown() { ASSERT_TRUE(heap.empty()); }

 protected:
  template <class Function>
  void StartThreads(unsigned int threads, Function&& func) {
    threads_.reserve(threads);
    tids_.reserve(threads);
    for (unsigned int i = 0; i < threads; i++) {
      threads_.emplace_back([&, threads, this]() {
        {
          std::lock_guard<std::mutex> lk(m_);
          tids_.push_back(gettid());
          if (tids_.size() == threads) {
            cv_start_.notify_one();
          }
        }

        func();

        {
          std::unique_lock<std::mutex> lk(m_);
          cv_stop_.wait(lk, [&] { return stop_; });
        }
      });
    }

    {
      std::unique_lock<std::mutex> lk(m_);
      cv_start_.wait(lk, [&] { return tids_.size() == threads; });
    }
  }

  void StopThreads() {
    {
      std::lock_guard<std::mutex> lk(m_);
      stop_ = true;
    }
    cv_stop_.notify_all();

    for (auto i = threads_.begin(); i != threads_.end(); i++) {
      i->join();
    }
    threads_.clear();
    tids_.clear();
  }

  std::vector<pid_t>& tids() { return tids_; }

  Heap heap;

 private:
  void WaitForThreads() {
    auto tids = TidList{heap};
    ThreadCapture thread_capture{getpid(), heap};

    for (unsigned int i = 0; i < 100; i++) {
      EXPECT_TRUE(thread_capture.ListThreads(tids));
      if (tids.size() == 1) {
        break;
      }
      std::this_thread::sleep_for(10ms);
    }
    EXPECT_EQ(1U, tids.size());
  }

  std::mutex m_;
  std::condition_variable cv_start_;
  std::condition_variable cv_stop_;
  bool stop_;
  std::vector<pid_t> tids_;

  std::vector<std::thread> threads_;
};

TEST_F(ThreadListTest, list_one) {
  ScopedDisableMallocTimeout disable_malloc;

  ThreadCapture thread_capture(getpid(), heap);

  auto expected_tids = allocator::vector<pid_t>(1, getpid(), heap);
  auto list_tids = allocator::vector<pid_t>(heap);

  ASSERT_TRUE(thread_capture.ListThreads(list_tids));

  ASSERT_EQ(expected_tids, list_tids);

  if (!HasFailure()) {
    ASSERT_FALSE(disable_malloc.timed_out());
  }
}

TEST_P(ThreadListTest, list_some) {
  const unsigned int threads = GetParam() - 1;

  StartThreads(threads, []() {});
  std::vector<pid_t> expected_tids = tids();
  expected_tids.push_back(getpid());

  auto list_tids = allocator::vector<pid_t>(heap);

  {
    ScopedDisableMallocTimeout disable_malloc;

    ThreadCapture thread_capture(getpid(), heap);

    ASSERT_TRUE(thread_capture.ListThreads(list_tids));

    if (!HasFailure()) {
      ASSERT_FALSE(disable_malloc.timed_out());
    }
  }

  StopThreads();

  std::sort(list_tids.begin(), list_tids.end());
  std::sort(expected_tids.begin(), expected_tids.end());

  ASSERT_EQ(expected_tids.size(), list_tids.size());
  EXPECT_TRUE(std::equal(expected_tids.begin(), expected_tids.end(), list_tids.begin()));
}

INSTANTIATE_TEST_CASE_P(ThreadListTest, ThreadListTest, ::testing::Values(1, 2, 10, 1024));

class ThreadCaptureTest : public ThreadListTest {
 public:
  ThreadCaptureTest() {}
  ~ThreadCaptureTest() {}
  void Fork(std::function<void()>&& child_init, std::function<void()>&& child_cleanup,
            std::function<void(pid_t)>&& parent) {
    ScopedPipe start_pipe;
    ScopedPipe stop_pipe;

    int pid = fork();

    if (pid == 0) {
      // child
      child_init();
      EXPECT_EQ(1, TEMP_FAILURE_RETRY(write(start_pipe.Sender(), "+", 1))) << strerror(errno);
      char buf;
      EXPECT_EQ(1, TEMP_FAILURE_RETRY(read(stop_pipe.Receiver(), &buf, 1))) << strerror(errno);
      child_cleanup();
      _exit(0);
    } else {
      // parent
      ASSERT_GT(pid, 0);
      char buf;
      ASSERT_EQ(1, TEMP_FAILURE_RETRY(read(start_pipe.Receiver(), &buf, 1))) << strerror(errno);

      parent(pid);

      ASSERT_EQ(1, TEMP_FAILURE_RETRY(write(stop_pipe.Sender(), "+", 1))) << strerror(errno);
      siginfo_t info{};
      ASSERT_EQ(0, TEMP_FAILURE_RETRY(waitid(P_PID, pid, &info, WEXITED))) << strerror(errno);
    }
  }
};

TEST_P(ThreadCaptureTest, capture_some) {
  const unsigned int threads = GetParam();

  Fork(
      [&]() {
        // child init
        StartThreads(threads - 1, []() {});
      },
      [&]() {
        // child cleanup
        StopThreads();
      },
      [&](pid_t child) {
        // parent
        ASSERT_GT(child, 0);

        {
          ScopedDisableMallocTimeout disable_malloc;

          ThreadCapture thread_capture(child, heap);
          auto list_tids = allocator::vector<pid_t>(heap);

          ASSERT_TRUE(thread_capture.ListThreads(list_tids));
          ASSERT_EQ(threads, list_tids.size());

          ASSERT_TRUE(thread_capture.CaptureThreads());

          auto thread_info = allocator::vector<ThreadInfo>(heap);
          ASSERT_TRUE(thread_capture.CapturedThreadInfo(thread_info));
          ASSERT_EQ(threads, thread_info.size());
          ASSERT_TRUE(thread_capture.ReleaseThreads());

          if (!HasFailure()) {
            ASSERT_FALSE(disable_malloc.timed_out());
          }
        }
      });
}

INSTANTIATE_TEST_CASE_P(ThreadCaptureTest, ThreadCaptureTest, ::testing::Values(1, 2, 10, 1024));

TEST_F(ThreadCaptureTest, capture_kill) {
  int ret = fork();

  if (ret == 0) {
    // child
    sleep(10);
  } else {
    // parent
    ASSERT_GT(ret, 0);

    {
      ScopedDisableMallocTimeout disable_malloc;

      ThreadCapture thread_capture(ret, heap);
      thread_capture.InjectTestFunc([&](pid_t tid) {
        syscall(SYS_tgkill, ret, tid, SIGKILL);
        usleep(10000);
      });
      auto list_tids = allocator::vector<pid_t>(heap);

      ASSERT_TRUE(thread_capture.ListThreads(list_tids));
      ASSERT_EQ(1U, list_tids.size());

      ASSERT_FALSE(thread_capture.CaptureThreads());

      if (!HasFailure()) {
        ASSERT_FALSE(disable_malloc.timed_out());
      }
    }
  }
}

TEST_F(ThreadCaptureTest, capture_signal) {
  const int sig = SIGUSR1;

  ScopedPipe pipe;

  // For signal handler
  static ScopedPipe* g_pipe;

  Fork(
      [&]() {
        // child init
        pipe.CloseReceiver();

        g_pipe = &pipe;

        struct sigaction act {};
        act.sa_handler = [](int) {
          char buf = '+';
          write(g_pipe->Sender(), &buf, 1);
          g_pipe->CloseSender();
        };
        sigaction(sig, &act, NULL);
        sigset_t set;
        sigemptyset(&set);
        sigaddset(&set, sig);
        pthread_sigmask(SIG_UNBLOCK, &set, NULL);
      },
      [&]() {
        // child cleanup
        g_pipe = nullptr;
        pipe.Close();
      },
      [&](pid_t child) {
        // parent
        ASSERT_GT(child, 0);
        pipe.CloseSender();

        {
          ScopedDisableMallocTimeout disable_malloc;

          ThreadCapture thread_capture(child, heap);
          thread_capture.InjectTestFunc([&](pid_t tid) {
            syscall(SYS_tgkill, child, tid, sig);
            usleep(10000);
          });
          auto list_tids = allocator::vector<pid_t>(heap);

          ASSERT_TRUE(thread_capture.ListThreads(list_tids));
          ASSERT_EQ(1U, list_tids.size());

          ASSERT_TRUE(thread_capture.CaptureThreads());

          auto thread_info = allocator::vector<ThreadInfo>(heap);
          ASSERT_TRUE(thread_capture.CapturedThreadInfo(thread_info));
          ASSERT_EQ(1U, thread_info.size());
          ASSERT_TRUE(thread_capture.ReleaseThreads());

          usleep(100000);
          char buf;
          ASSERT_EQ(1, TEMP_FAILURE_RETRY(read(pipe.Receiver(), &buf, 1)));
          ASSERT_EQ(buf, '+');

          if (!HasFailure()) {
            ASSERT_FALSE(disable_malloc.timed_out());
          }
        }
      });
}

}  // namespace android
