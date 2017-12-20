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

#include <err.h>
#include <errno.h>
#include <sched.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <thread>

#include <benchmark/benchmark.h>
#include <debuggerd/client.h>

using namespace std::chrono_literals;

static_assert(std::chrono::high_resolution_clock::is_steady);

enum class ThreadState { Starting, Started, Stopping };

static void SetScheduler() {
  struct sched_param param {
    .sched_priority = 1,
  };

  if (sched_setscheduler(getpid(), SCHED_FIFO, &param) != 0) {
    fprintf(stderr, "failed to set scheduler to SCHED_FIFO: %s", strerror(errno));
  }
}

static std::chrono::duration<double> GetMaximumPause(std::atomic<ThreadState>& state) {
  std::chrono::duration<double> max_diff(0);

  const auto begin = std::chrono::high_resolution_clock::now();
  auto last = begin;
  state.store(ThreadState::Started);
  while (state.load() != ThreadState::Stopping) {
    auto now = std::chrono::high_resolution_clock::now();

    auto diff = now - last;
    if (diff > max_diff) {
      max_diff = diff;
    }

    last = now;
  }

  return max_diff;
}

static void PerformDump() {
  pid_t target = getpid();
  pid_t forkpid = fork();
  if (forkpid == -1) {
    err(1, "fork failed");
  } else if (forkpid != 0) {
    int status;
    pid_t pid = waitpid(forkpid, &status, 0);
    if (pid == -1) {
      err(1, "waitpid failed");
    } else if (!WIFEXITED(status)) {
      err(1, "child didn't exit");
    } else if (WEXITSTATUS(status) != 0) {
      errx(1, "child exited with non-zero status %d", WEXITSTATUS(status));
    }
  } else {
    android::base::unique_fd output_fd(open("/dev/null", O_WRONLY | O_CLOEXEC));
    if (output_fd == -1) {
      err(1, "failed to open /dev/null");
    }

    if (!debuggerd_trigger_dump(target, kDebuggerdNativeBacktrace, 1000, std::move(output_fd))) {
      errx(1, "failed to trigger dump");
    }

    _exit(0);
  }
}

template <typename Fn>
static void BM_maximum_pause_impl(benchmark::State& state, const Fn& function) {
  SetScheduler();

  for (auto _ : state) {
    std::chrono::duration<double> max_pause;
    std::atomic<ThreadState> thread_state(ThreadState::Starting);
    auto thread = std::thread([&]() { max_pause = GetMaximumPause(thread_state); });

    while (thread_state != ThreadState::Started) {
      std::this_thread::sleep_for(1ms);
    }

    function();

    thread_state = ThreadState::Stopping;
    thread.join();

    state.SetIterationTime(max_pause.count());
  }
}

static void BM_maximum_pause_noop(benchmark::State& state) {
  BM_maximum_pause_impl(state, []() {});
}

static void BM_maximum_pause_debuggerd(benchmark::State& state) {
  BM_maximum_pause_impl(state, []() { PerformDump(); });
}

BENCHMARK(BM_maximum_pause_noop)->Iterations(128)->UseManualTime();
BENCHMARK(BM_maximum_pause_debuggerd)->Iterations(128)->UseManualTime();

BENCHMARK_MAIN();
