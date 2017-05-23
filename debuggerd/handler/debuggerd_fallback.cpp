/*
 * Copyright (C) 2017 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
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

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>

#include "debuggerd/handler.h"
#include "tombstoned/tombstoned.h"
#include "util.h"

#include "backtrace.h"
#include "tombstone.h"

using android::base::unique_fd;

extern "C" void __linker_enable_fallback_allocator();
extern "C" void __linker_disable_fallback_allocator();

// This is incredibly sketchy to do inside of a signal handler, especially when libbacktrace
// uses the C++ standard library throughout, but this code runs in the linker, so we'll be using
// the linker's malloc instead of the libc one. Switch it out for a replacement, just in case.
//
// This isn't the default method of dumping because it can fail in cases such as address space
// exhaustion.
static void debuggerd_fallback_trace(int output_fd, ucontext_t* ucontext) {
  __linker_enable_fallback_allocator();
  dump_backtrace_ucontext(output_fd, ucontext);
  __linker_disable_fallback_allocator();
}

static void debuggerd_fallback_tombstone(int output_fd, ucontext_t* ucontext, siginfo_t* siginfo,
                                         void* abort_message) {
  __linker_enable_fallback_allocator();
  engrave_tombstone_ucontext(output_fd, reinterpret_cast<uintptr_t>(abort_message), siginfo,
                             ucontext);
  __linker_disable_fallback_allocator();
}

static void iterate_siblings(bool (*callback)(pid_t, int), int output_fd) {
  pid_t current_tid = gettid();
  char buf[BUFSIZ];
  snprintf(buf, sizeof(buf), "/proc/%d/task", current_tid);
  DIR* dir = opendir(buf);

  if (!dir) {
    async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to open %s: %s", buf, strerror(errno));
    return;
  }

  struct dirent* ent;
  while ((ent = readdir(dir))) {
    char* end;
    long tid = strtol(ent->d_name, &end, 10);
    if (end == ent->d_name || *end != '\0') {
      continue;
    }

    if (tid != current_tid) {
      callback(tid, output_fd);
    }
  }
  closedir(dir);
}

static bool forward_output(int src_fd, int dst_fd) {
  // Make sure the thread actually got the signal.
  struct pollfd pfd = {
    .fd = src_fd, .events = POLLIN,
  };

  // Wait for up to a second for output to start flowing.
  if (poll(&pfd, 1, 1000) != 1) {
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

static void trace_handler(siginfo_t* info, ucontext_t* ucontext) {
  static std::atomic<int> trace_output_fd(-1);

  if (info->si_value.sival_int == ~0) {
    // Asked to dump by the original signal recipient.
    debuggerd_fallback_trace(trace_output_fd, ucontext);

    int tmp = trace_output_fd.load();
    trace_output_fd.store(-1);
    close(tmp);
    return;
  }

  // Only allow one thread to perform a trace at a time.
  static pthread_mutex_t trace_mutex = PTHREAD_MUTEX_INITIALIZER;
  int ret = pthread_mutex_trylock(&trace_mutex);
  if (ret != 0) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc", "pthread_mutex_try_lock failed: %s",
                          strerror(ret));
    return;
  }

  // Fetch output fd from tombstoned.
  unique_fd tombstone_socket, output_fd;
  if (!tombstoned_connect(getpid(), &tombstone_socket, &output_fd)) {
    goto exit;
  }

  dump_backtrace_header(output_fd.get());

  // Dump our own stack.
  debuggerd_fallback_trace(output_fd.get(), ucontext);

  // Send a signal to all of our siblings, asking them to dump their stack.
  iterate_siblings(
    [](pid_t tid, int output_fd) {
      // Use a pipe, to be able to detect situations where the thread gracefully exits before
      // receiving our signal.
      unique_fd pipe_read, pipe_write;
      if (!Pipe(&pipe_read, &pipe_write)) {
        async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to create pipe: %s",
                              strerror(errno));
        return false;
      }

      trace_output_fd.store(pipe_write.get());

      siginfo_t siginfo = {};
      siginfo.si_code = SI_QUEUE;
      siginfo.si_value.sival_int = ~0;
      siginfo.si_pid = getpid();
      siginfo.si_uid = getuid();

      if (syscall(__NR_rt_tgsigqueueinfo, getpid(), tid, DEBUGGER_SIGNAL, &siginfo) != 0) {
        async_safe_format_log(ANDROID_LOG_ERROR, "libc", "failed to send trace signal to %d: %s",
                              tid, strerror(errno));
        return false;
      }

      bool success = forward_output(pipe_read.get(), output_fd);
      if (success) {
        // The signaled thread has closed trace_output_fd already.
        (void)pipe_write.release();
      } else {
        trace_output_fd.store(-1);
      }

      return true;
    },
    output_fd.get());

  dump_backtrace_footer(output_fd.get());
  tombstoned_notify_completion(tombstone_socket.get());

exit:
  pthread_mutex_unlock(&trace_mutex);
}

static void crash_handler(siginfo_t* info, ucontext_t* ucontext, void* abort_message) {
  // Only allow one thread to handle a crash.
  static pthread_mutex_t crash_mutex = PTHREAD_MUTEX_INITIALIZER;
  int ret = pthread_mutex_lock(&crash_mutex);
  if (ret != 0) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc", "pthread_mutex_lock failed: %s", strerror(ret));
    return;
  }

  unique_fd tombstone_socket, output_fd;
  bool tombstoned_connected = tombstoned_connect(getpid(), &tombstone_socket, &output_fd);
  debuggerd_fallback_tombstone(output_fd.get(), ucontext, info, abort_message);
  if (tombstoned_connected) {
    tombstoned_notify_completion(tombstone_socket.get());
  }
}

extern "C" void debuggerd_fallback_handler(siginfo_t* info, ucontext_t* ucontext,
                                           void* abort_message) {
  if (info->si_signo == DEBUGGER_SIGNAL) {
    return trace_handler(info, ucontext);
  } else {
    return crash_handler(info, ucontext, abort_message);
  }
}
