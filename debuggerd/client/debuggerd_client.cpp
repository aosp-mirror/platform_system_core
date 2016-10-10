/*
 * Copyright (C) 2008 The Android Open Source Project
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

#include "debuggerd/client.h"

#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "private/libc_logging.h"

#if defined(TARGET_IS_64_BIT) && !defined(__LP64__)
#define SOCKET_NAME "android:debuggerd32"
#else
#define SOCKET_NAME "android:debuggerd"
#endif

// see man(2) prctl, specifically the section about PR_GET_NAME
#define MAX_TASK_NAME_LEN (16)

static debuggerd_callbacks_t g_callbacks;

// Don't use __libc_fatal because it exits via abort, which might put us back into a signal handler.
#define fatal(...)                                             \
  do {                                                         \
    __libc_format_log(ANDROID_LOG_FATAL, "libc", __VA_ARGS__); \
    _exit(1);                                                  \
  } while (0)

static int socket_abstract_client(const char* name, int type) {
  sockaddr_un addr;

  // Test with length +1 for the *initial* '\0'.
  size_t namelen = strlen(name);
  if ((namelen + 1) > sizeof(addr.sun_path)) {
    errno = EINVAL;
    return -1;
  }

  // This is used for abstract socket namespace, we need
  // an initial '\0' at the start of the Unix socket path.
  //
  // Note: The path in this case is *not* supposed to be
  // '\0'-terminated. ("man 7 unix" for the gory details.)
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_LOCAL;
  addr.sun_path[0] = 0;
  memcpy(addr.sun_path + 1, name, namelen);

  socklen_t alen = namelen + offsetof(sockaddr_un, sun_path) + 1;

  int s = socket(AF_LOCAL, type, 0);
  if (s == -1) {
    return -1;
  }

  int rc = TEMP_FAILURE_RETRY(connect(s, reinterpret_cast<sockaddr*>(&addr), alen));
  if (rc == -1) {
    close(s);
    return -1;
  }

  return s;
}

/*
 * Writes a summary of the signal to the log file.  We do this so that, if
 * for some reason we're not able to contact debuggerd, there is still some
 * indication of the failure in the log.
 *
 * We could be here as a result of native heap corruption, or while a
 * mutex is being held, so we don't want to use any libc functions that
 * could allocate memory or hold a lock.
 */
static void log_signal_summary(int signum, const siginfo_t* info) {
  const char* signal_name = "???";
  bool has_address = false;
  switch (signum) {
    case SIGABRT:
      signal_name = "SIGABRT";
      break;
    case SIGBUS:
      signal_name = "SIGBUS";
      has_address = true;
      break;
    case SIGFPE:
      signal_name = "SIGFPE";
      has_address = true;
      break;
    case SIGILL:
      signal_name = "SIGILL";
      has_address = true;
      break;
    case SIGSEGV:
      signal_name = "SIGSEGV";
      has_address = true;
      break;
#if defined(SIGSTKFLT)
    case SIGSTKFLT:
      signal_name = "SIGSTKFLT";
      break;
#endif
    case SIGSYS:
      signal_name = "SIGSYS";
      break;
    case SIGTRAP:
      signal_name = "SIGTRAP";
      break;
  }

  char thread_name[MAX_TASK_NAME_LEN + 1];  // one more for termination
  if (prctl(PR_GET_NAME, reinterpret_cast<unsigned long>(thread_name), 0, 0, 0) != 0) {
    strcpy(thread_name, "<name unknown>");
  } else {
    // short names are null terminated by prctl, but the man page
    // implies that 16 byte names are not.
    thread_name[MAX_TASK_NAME_LEN] = 0;
  }

  // "info" will be null if the siginfo_t information was not available.
  // Many signals don't have an address or a code.
  char code_desc[32];  // ", code -6"
  char addr_desc[32];  // ", fault addr 0x1234"
  addr_desc[0] = code_desc[0] = 0;
  if (info != nullptr) {
    // For a rethrown signal, this si_code will be right and the one debuggerd shows will
    // always be SI_TKILL.
    __libc_format_buffer(code_desc, sizeof(code_desc), ", code %d", info->si_code);
    if (has_address) {
      __libc_format_buffer(addr_desc, sizeof(addr_desc), ", fault addr %p", info->si_addr);
    }
  }
  __libc_format_log(ANDROID_LOG_FATAL, "libc", "Fatal signal %d (%s)%s%s in tid %d (%s)", signum,
                    signal_name, code_desc, addr_desc, gettid(), thread_name);
}

/*
 * Returns true if the handler for signal "signum" has SA_SIGINFO set.
 */
static bool have_siginfo(int signum) {
  struct sigaction old_action, new_action;

  memset(&new_action, 0, sizeof(new_action));
  new_action.sa_handler = SIG_DFL;
  new_action.sa_flags = SA_RESTART;
  sigemptyset(&new_action.sa_mask);

  if (sigaction(signum, &new_action, &old_action) < 0) {
    __libc_format_log(ANDROID_LOG_WARN, "libc", "Failed testing for SA_SIGINFO: %s",
                      strerror(errno));
    return false;
  }
  bool result = (old_action.sa_flags & SA_SIGINFO) != 0;

  if (sigaction(signum, &old_action, nullptr) == -1) {
    __libc_format_log(ANDROID_LOG_WARN, "libc", "Restore failed in test for SA_SIGINFO: %s",
                      strerror(errno));
  }
  return result;
}

static void send_debuggerd_packet(pid_t crashing_tid, pid_t pseudothread_tid) {
  // Mutex to prevent multiple crashing threads from trying to talk
  // to debuggerd at the same time.
  static pthread_mutex_t crash_mutex = PTHREAD_MUTEX_INITIALIZER;
  int ret = pthread_mutex_trylock(&crash_mutex);
  if (ret != 0) {
    if (ret == EBUSY) {
      __libc_format_log(ANDROID_LOG_INFO, "libc",
                        "Another thread contacted debuggerd first; not contacting debuggerd.");
      // This will never complete since the lock is never released.
      pthread_mutex_lock(&crash_mutex);
    } else {
      __libc_format_log(ANDROID_LOG_INFO, "libc", "pthread_mutex_trylock failed: %s", strerror(ret));
    }
    return;
  }

  int s = socket_abstract_client(SOCKET_NAME, SOCK_STREAM | SOCK_CLOEXEC);
  if (s == -1) {
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "Unable to open connection to debuggerd: %s",
                      strerror(errno));
    return;
  }

  // debuggerd knows our pid from the credentials on the
  // local socket but we need to tell it the tid of the crashing thread.
  // debuggerd will be paranoid and verify that we sent a tid
  // that's actually in our process.
  debugger_msg_t msg;
  msg.action = DEBUGGER_ACTION_CRASH;
  msg.tid = crashing_tid;
  msg.ignore_tid = pseudothread_tid;
  msg.abort_msg_address = 0;

  if (g_callbacks.get_abort_message) {
    msg.abort_msg_address = reinterpret_cast<uintptr_t>(g_callbacks.get_abort_message());
  }

  ret = TEMP_FAILURE_RETRY(write(s, &msg, sizeof(msg)));
  if (ret == sizeof(msg)) {
    char debuggerd_ack;
    ret = TEMP_FAILURE_RETRY(read(s, &debuggerd_ack, 1));
    if (g_callbacks.post_dump) {
      g_callbacks.post_dump();
    }
  } else {
    // read or write failed -- broken connection?
    __libc_format_log(ANDROID_LOG_FATAL, "libc", "Failed while talking to debuggerd: %s",
                      strerror(errno));
  }

  close(s);
}

struct debugger_thread_info {
  pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pid_t crashing_tid;
  pid_t pseudothread_tid;
  int signal_number;
  siginfo_t* info;
};

// Logging and contacting debuggerd requires free file descriptors, which we might not have.
// Work around this by spawning a "thread" that shares its parent's address space, but not its file
// descriptor table, so that we can close random file descriptors without affecting the original
// process. Note that this doesn't go through pthread_create, so TLS is shared with the spawning
// process.
static void* pseudothread_stack;
static int debuggerd_dispatch_pseudothread(void* arg) {
  debugger_thread_info* thread_info = static_cast<debugger_thread_info*>(arg);

  for (int i = 3; i < 1024; ++i) {
    close(i);
  }

  log_signal_summary(thread_info->signal_number, thread_info->info);
  send_debuggerd_packet(thread_info->crashing_tid, thread_info->pseudothread_tid);
  pthread_mutex_unlock(&thread_info->mutex);
  return 0;
}

/*
 * Catches fatal signals so we can ask debuggerd to ptrace us before
 * we crash.
 */
static void debuggerd_signal_handler(int signal_number, siginfo_t* info, void*) {
  // It's possible somebody cleared the SA_SIGINFO flag, which would mean
  // our "info" arg holds an undefined value.
  if (!have_siginfo(signal_number)) {
    info = nullptr;
  }

  debugger_thread_info thread_info = {
    .crashing_tid = gettid(),
    .signal_number = signal_number,
    .info = info
  };

  pthread_mutex_lock(&thread_info.mutex);
  pid_t child_pid = clone(debuggerd_dispatch_pseudothread, pseudothread_stack,
                          CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_CHILD_SETTID,
                          &thread_info, nullptr, nullptr, &thread_info.pseudothread_tid);

  if (child_pid == -1) {
    fatal("failed to spawn debuggerd dispatch thread: %s", strerror(errno));
  }

  // Wait for the child to finish and unlock the mutex.
  // This relies on bionic behavior that isn't guaranteed by the standard.
  pthread_mutex_lock(&thread_info.mutex);


  // We need to return from the signal handler so that debuggerd can dump the
  // thread that crashed, but returning here does not guarantee that the signal
  // will be thrown again, even for SIGSEGV and friends, since the signal could
  // have been sent manually. Resend the signal with rt_tgsigqueueinfo(2) to
  // preserve the SA_SIGINFO contents.
  signal(signal_number, SIG_DFL);

  struct siginfo si;
  if (!info) {
    memset(&si, 0, sizeof(si));
    si.si_code = SI_USER;
    si.si_pid = getpid();
    si.si_uid = getuid();
    info = &si;
  } else if (info->si_code >= 0 || info->si_code == SI_TKILL) {
    // rt_tgsigqueueinfo(2)'s documentation appears to be incorrect on kernels
    // that contain commit 66dd34a (3.9+). The manpage claims to only allow
    // negative si_code values that are not SI_TKILL, but 66dd34a changed the
    // check to allow all si_code values in calls coming from inside the house.
  }

  int rc = syscall(SYS_rt_tgsigqueueinfo, getpid(), gettid(), signal_number, info);
  if (rc != 0) {
    fatal("failed to resend signal during crash: %s", strerror(errno));
  }
}

void debuggerd_init(debuggerd_callbacks_t* callbacks) {
  if (callbacks) {
    g_callbacks = *callbacks;
  }

  void* thread_stack_allocation =
    mmap(nullptr, PAGE_SIZE * 3, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (thread_stack_allocation == MAP_FAILED) {
    fatal("failed to allocate debuggerd thread stack");
  }

  char* stack = static_cast<char*>(thread_stack_allocation) + PAGE_SIZE;
  if (mprotect(stack, PAGE_SIZE, PROT_READ | PROT_WRITE) != 0) {
    fatal("failed to mprotect debuggerd thread stack");
  }

  // Stack grows negatively, set it to the last byte in the page...
  stack = (stack + PAGE_SIZE - 1);
  // and align it.
  stack -= 15;
  pseudothread_stack = stack;

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  sigemptyset(&action.sa_mask);
  action.sa_sigaction = debuggerd_signal_handler;
  action.sa_flags = SA_RESTART | SA_SIGINFO;

  // Use the alternate signal stack if available so we can catch stack overflows.
  action.sa_flags |= SA_ONSTACK;

  sigaction(SIGABRT, &action, nullptr);
  sigaction(SIGBUS, &action, nullptr);
  sigaction(SIGFPE, &action, nullptr);
  sigaction(SIGILL, &action, nullptr);
  sigaction(SIGSEGV, &action, nullptr);
#if defined(SIGSTKFLT)
  sigaction(SIGSTKFLT, &action, nullptr);
#endif
  sigaction(SIGTRAP, &action, nullptr);
}
