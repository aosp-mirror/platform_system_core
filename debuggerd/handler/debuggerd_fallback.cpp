/*
 * Copyright 2017 The Android Open Source Project
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

#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stddef.h>
#include <sys/ucontext.h>
#include <syscall.h>
#include <unistd.h>

#include <atomic>
#include <memory>
#include <mutex>

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <bionic/reserved_signals.h>
#include <unwindstack/DexFiles.h>
#include <unwindstack/JitDebug.h>
#include <unwindstack/Maps.h>
#include <unwindstack/Memory.h>
#include <unwindstack/Regs.h>
#include <unwindstack/Unwinder.h>

#include "debuggerd/handler.h"
#include "handler/fallback.h"
#include "tombstoned/tombstoned.h"
#include "util.h"

#include "libdebuggerd/backtrace.h"
#include "libdebuggerd/tombstone.h"

using android::base::unique_fd;

extern "C" bool __linker_enable_fallback_allocator();
extern "C" void __linker_disable_fallback_allocator();

// This is incredibly sketchy to do inside of a signal handler, especially when libbacktrace
// uses the C++ standard library throughout, but this code runs in the linker, so we'll be using
// the linker's malloc instead of the libc one. Switch it out for a replacement, just in case.
//
// This isn't the default method of dumping because it can fail in cases such as address space
// exhaustion.
static void debuggerd_fallback_trace(int output_fd, ucontext_t* ucontext) {
  if (!__linker_enable_fallback_allocator()) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "fallback allocator already in use");
    return;
  }

  {
    std::unique_ptr<unwindstack::Regs> regs;

    ThreadInfo thread;
    thread.pid = getpid();
    thread.tid = gettid();
    thread.thread_name = get_thread_name(gettid());
    thread.registers.reset(
        unwindstack::Regs::CreateFromUcontext(unwindstack::Regs::CurrentArch(), ucontext));

    // Do not use the thread cache here because it will call pthread_key_create
    // which doesn't work in linker code. See b/189803009.
    // Use a normal cached object because the process is stopped, and there
    // is no chance of data changing between reads.
    auto process_memory = unwindstack::Memory::CreateProcessMemoryCached(getpid());
    // TODO: Create this once and store it in a global?
    unwindstack::UnwinderFromPid unwinder(kMaxFrames, getpid(), process_memory);
    dump_backtrace_thread(output_fd, &unwinder, thread);
  }
  __linker_disable_fallback_allocator();
}

static void debuggerd_fallback_tombstone(int output_fd, int proto_fd, ucontext_t* ucontext,
                                         siginfo_t* siginfo, void* abort_message) {
  if (!__linker_enable_fallback_allocator()) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "fallback allocator already in use");
    return;
  }

  engrave_tombstone_ucontext(output_fd, proto_fd, reinterpret_cast<uintptr_t>(abort_message),
                             siginfo, ucontext);
  __linker_disable_fallback_allocator();
}

static bool forward_output(int src_fd, int dst_fd, pid_t expected_tid) {
  // Make sure the thread actually got the signal.
  struct pollfd pfd = {
    .fd = src_fd, .events = POLLIN,
  };

  // Wait for up to a second for output to start flowing.
  if (poll(&pfd, 1, 1000) != 1) {
    return false;
  }

  pid_t tid;
  if (TEMP_FAILURE_RETRY(read(src_fd, &tid, sizeof(tid))) != sizeof(tid)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to read tid");
    return false;
  }

  if (tid != expected_tid) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "received tid %d, expected %d", tid,
                          expected_tid);
    return false;
  }

  while (true) {
    char buf[512];
    ssize_t rc = TEMP_FAILURE_RETRY(read(src_fd, buf, sizeof(buf)));
    if (rc == 0) {
      return true;
    } else if (rc < 0) {
      return false;
    }

    if (!android::base::WriteFully(dst_fd, buf, rc)) {
      // We failed to write to tombstoned, but there's not much we can do.
      // Keep reading from src_fd to keep things going.
      continue;
    }
  }
}

struct __attribute__((__packed__)) packed_thread_output {
  int32_t tid;
  int32_t fd;
};

static uint64_t pack_thread_fd(pid_t tid, int fd) {
  packed_thread_output packed = {.tid = tid, .fd = fd};
  uint64_t result;
  static_assert(sizeof(packed) == sizeof(result));
  memcpy(&result, &packed, sizeof(packed));
  return result;
}

static std::pair<pid_t, int> unpack_thread_fd(uint64_t value) {
  packed_thread_output result;
  memcpy(&result, &value, sizeof(value));
  return std::make_pair(result.tid, result.fd);
}

static void trace_handler(siginfo_t* info, ucontext_t* ucontext) {
  static std::atomic<uint64_t> trace_output(pack_thread_fd(-1, -1));

  if (info->si_value.sival_ptr == kDebuggerdFallbackSivalPtrRequestDump) {
    // Asked to dump by the original signal recipient.
    uint64_t val = trace_output.load();
    auto [tid, fd] = unpack_thread_fd(val);
    if (tid != gettid()) {
      // We received some other thread's info request?
      async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                            "thread %d received output fd for thread %d?", gettid(), tid);
      return;
    }

    if (!trace_output.compare_exchange_strong(val, pack_thread_fd(-1, -1))) {
      // Presumably, the timeout in forward_output expired, and the main thread moved on.
      // If this happened, the main thread closed our fd for us, so just return.
      async_safe_format_log(ANDROID_LOG_ERROR, "libc", "cmpxchg for thread %d failed", gettid());
      return;
    }

    // Write our tid to the output fd to let the main thread know that we're working.
    if (TEMP_FAILURE_RETRY(write(fd, &tid, sizeof(tid))) == sizeof(tid)) {
      debuggerd_fallback_trace(fd, ucontext);
    } else {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to write to output fd");
    }

    close(fd);
    return;
  }

  // Only allow one thread to perform a trace at a time.
  static std::mutex trace_mutex;
  if (!trace_mutex.try_lock()) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc", "trace lock failed");
    return;
  }

  std::lock_guard<std::mutex> scoped_lock(trace_mutex, std::adopt_lock);

  // Fetch output fd from tombstoned.
  unique_fd tombstone_socket, output_fd;
  if (!tombstoned_connect(getpid(), &tombstone_socket, &output_fd, nullptr,
                          kDebuggerdNativeBacktrace)) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "missing crash_dump_fallback() in selinux policy?");
    return;
  }

  dump_backtrace_header(output_fd.get());

  // Dump our own stack.
  debuggerd_fallback_trace(output_fd.get(), ucontext);

  // Send a signal to all of our siblings, asking them to dump their stack.
  pid_t current_tid = gettid();
  if (!iterate_tids(current_tid, [&output_fd](pid_t tid) {
        // Use a pipe, to be able to detect situations where the thread gracefully exits before
        // receiving our signal.
        unique_fd pipe_read, pipe_write;
        if (!Pipe(&pipe_read, &pipe_write)) {
          async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to create pipe: %s",
                                strerror(errno));
          return;
        }

        uint64_t expected = pack_thread_fd(-1, -1);
        int sent_fd = pipe_write.release();
        if (!trace_output.compare_exchange_strong(expected, pack_thread_fd(tid, sent_fd))) {
          auto [tid, fd] = unpack_thread_fd(expected);
          async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                                "thread %d is already outputting to fd %d?", tid, fd);
          close(sent_fd);
          return;
        }

        siginfo_t siginfo = {};
        siginfo.si_code = SI_QUEUE;
        siginfo.si_value.sival_ptr = kDebuggerdFallbackSivalPtrRequestDump;
        siginfo.si_pid = getpid();
        siginfo.si_uid = getuid();

        if (syscall(__NR_rt_tgsigqueueinfo, getpid(), tid, BIONIC_SIGNAL_DEBUGGER, &siginfo) != 0) {
          async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to send trace signal to %d: %s",
                                tid, strerror(errno));
          return;
        }

        bool success = forward_output(pipe_read.get(), output_fd.get(), tid);
        if (!success) {
          async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                                "timeout expired while waiting for thread %d to dump", tid);
        }

        // Regardless of whether the poll succeeds, check to see if the thread took fd ownership.
        uint64_t post_wait = trace_output.exchange(pack_thread_fd(-1, -1));
        if (post_wait != pack_thread_fd(-1, -1)) {
          auto [tid, fd] = unpack_thread_fd(post_wait);
          if (fd != -1) {
            async_safe_format_log(ANDROID_LOG_ERROR, "libc", "closing fd %d for thread %d", fd, tid);
            close(fd);
          }
        }

        return;
      })) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to open /proc/%d/task: %s",
                          current_tid, strerror(errno));
  }

  dump_backtrace_footer(output_fd.get());
  tombstoned_notify_completion(tombstone_socket.get());
}

static void crash_handler(siginfo_t* info, ucontext_t* ucontext, void* abort_message) {
  // Only allow one thread to handle a crash at a time (this can happen multiple times without
  // exit, since tombstones can be requested without a real crash happening.)
  static std::recursive_mutex crash_mutex;
  static int lock_count;

  crash_mutex.lock();
  if (lock_count++ > 0) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "recursed signal handler call, aborting");
    signal(SIGABRT, SIG_DFL);
    raise(SIGABRT);
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGABRT);
    sigprocmask(SIG_UNBLOCK, &sigset, nullptr);

    // Just in case...
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "abort didn't exit, exiting");
    _exit(1);
  }

  unique_fd tombstone_socket, output_fd, proto_fd;
  bool tombstoned_connected = tombstoned_connect(getpid(), &tombstone_socket, &output_fd, &proto_fd,
                                                 kDebuggerdTombstoneProto);
  debuggerd_fallback_tombstone(output_fd.get(), proto_fd.get(), ucontext, info, abort_message);
  if (tombstoned_connected) {
    tombstoned_notify_completion(tombstone_socket.get());
  }

  --lock_count;
  crash_mutex.unlock();
}

extern "C" void debuggerd_fallback_handler(siginfo_t* info, ucontext_t* ucontext,
                                           void* abort_message) {
  if (info->si_signo == BIONIC_SIGNAL_DEBUGGER && info->si_value.sival_ptr != nullptr) {
    return trace_handler(info, ucontext);
  } else {
    return crash_handler(info, ucontext, abort_message);
  }
}
