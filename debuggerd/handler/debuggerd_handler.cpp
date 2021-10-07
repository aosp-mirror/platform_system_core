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

#include "debuggerd/handler.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <bionic/reserved_signals.h>

#include <libdebuggerd/utility.h>

#include "dump_type.h"
#include "protocol.h"

#include "handler/fallback.h"

using android::base::Pipe;

// We muck with our fds in a 'thread' that doesn't share the same fd table.
// Close fds in that thread with a raw close syscall instead of going through libc.
struct FdsanBypassCloser {
  static void Close(int fd) {
    syscall(__NR_close, fd);
  }
};

using unique_fd = android::base::unique_fd_impl<FdsanBypassCloser>;

// see man(2) prctl, specifically the section about PR_GET_NAME
#define MAX_TASK_NAME_LEN (16)

#if defined(__LP64__)
#define CRASH_DUMP_NAME "crash_dump64"
#else
#define CRASH_DUMP_NAME "crash_dump32"
#endif

#define CRASH_DUMP_PATH "/apex/com.android.runtime/bin/" CRASH_DUMP_NAME

// Wrappers that directly invoke the respective syscalls, in case the cached values are invalid.
#pragma GCC poison getpid gettid
static pid_t __getpid() {
  return syscall(__NR_getpid);
}

static pid_t __gettid() {
  return syscall(__NR_gettid);
}

static inline void futex_wait(volatile void* ftx, int value) {
  syscall(__NR_futex, ftx, FUTEX_WAIT, value, nullptr, nullptr, 0);
}

class ErrnoRestorer {
 public:
  ErrnoRestorer() : saved_errno_(errno) {
  }

  ~ErrnoRestorer() {
    errno = saved_errno_;
  }

 private:
  int saved_errno_;
};

extern "C" void* android_fdsan_get_fd_table();
extern "C" void debuggerd_fallback_handler(siginfo_t*, ucontext_t*, void*);

static debuggerd_callbacks_t g_callbacks;

// Mutex to ensure only one crashing thread dumps itself.
static pthread_mutex_t crash_mutex = PTHREAD_MUTEX_INITIALIZER;

// Don't use async_safe_fatal because it exits via abort, which might put us back into
// a signal handler.
static void __noreturn __printflike(1, 2) fatal(const char* fmt, ...) {
  va_list args;
  va_start(args, fmt);
  async_safe_format_log_va_list(ANDROID_LOG_FATAL, "libc", fmt, args);
  _exit(1);
}

static void __noreturn __printflike(1, 2) fatal_errno(const char* fmt, ...) {
  int err = errno;
  va_list args;
  va_start(args, fmt);

  char buf[256];
  async_safe_format_buffer_va_list(buf, sizeof(buf), fmt, args);
  fatal("%s: %s", buf, strerror(err));
}

static bool get_main_thread_name(char* buf, size_t len) {
  unique_fd fd(open("/proc/self/comm", O_RDONLY | O_CLOEXEC));
  if (fd == -1) {
    return false;
  }

  ssize_t rc = read(fd, buf, len);
  if (rc == -1) {
    return false;
  } else if (rc == 0) {
    // Should never happen?
    return false;
  }

  // There's a trailing newline, replace it with a NUL.
  buf[rc - 1] = '\0';
  return true;
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
static void log_signal_summary(const siginfo_t* info) {
  char thread_name[MAX_TASK_NAME_LEN + 1];  // one more for termination
  if (prctl(PR_GET_NAME, reinterpret_cast<unsigned long>(thread_name), 0, 0, 0) != 0) {
    strcpy(thread_name, "<name unknown>");
  } else {
    // short names are null terminated by prctl, but the man page
    // implies that 16 byte names are not.
    thread_name[MAX_TASK_NAME_LEN] = 0;
  }

  if (info->si_signo == BIONIC_SIGNAL_DEBUGGER) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc", "Requested dump for tid %d (%s)", __gettid(),
                          thread_name);
    return;
  }

  // Many signals don't have an address or sender.
  char addr_desc[32] = "";  // ", fault addr 0x1234"
  if (signal_has_si_addr(info)) {
    async_safe_format_buffer(addr_desc, sizeof(addr_desc), ", fault addr %p", info->si_addr);
  }
  pid_t self_pid = __getpid();
  char sender_desc[32] = {};  // " from pid 1234, uid 666"
  if (signal_has_sender(info, self_pid)) {
    get_signal_sender(sender_desc, sizeof(sender_desc), info);
  }

  char main_thread_name[MAX_TASK_NAME_LEN + 1];
  if (!get_main_thread_name(main_thread_name, sizeof(main_thread_name))) {
    strncpy(main_thread_name, "<unknown>", sizeof(main_thread_name));
  }

  async_safe_format_log(ANDROID_LOG_FATAL, "libc",
                        "Fatal signal %d (%s), code %d (%s%s)%s in tid %d (%s), pid %d (%s)",
                        info->si_signo, get_signame(info), info->si_code, get_sigcode(info),
                        sender_desc, addr_desc, __gettid(), thread_name, self_pid, main_thread_name);
}

/*
 * Returns true if the handler for signal "signum" has SA_SIGINFO set.
 */
static bool have_siginfo(int signum) {
  struct sigaction old_action;
  if (sigaction(signum, nullptr, &old_action) < 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "Failed testing for SA_SIGINFO: %s",
                          strerror(errno));
    return false;
  }
  return (old_action.sa_flags & SA_SIGINFO) != 0;
}

static void raise_caps() {
  // Raise CapInh to match CapPrm, so that we can set the ambient bits.
  __user_cap_header_struct capheader;
  memset(&capheader, 0, sizeof(capheader));
  capheader.version = _LINUX_CAPABILITY_VERSION_3;
  capheader.pid = 0;

  __user_cap_data_struct capdata[2];
  if (capget(&capheader, &capdata[0]) == -1) {
    fatal_errno("capget failed");
  }

  if (capdata[0].permitted != capdata[0].inheritable ||
      capdata[1].permitted != capdata[1].inheritable) {
    capdata[0].inheritable = capdata[0].permitted;
    capdata[1].inheritable = capdata[1].permitted;

    if (capset(&capheader, &capdata[0]) == -1) {
      async_safe_format_log(ANDROID_LOG_ERROR, "libc", "capset failed: %s", strerror(errno));
    }
  }

  // Set the ambient capability bits so that crash_dump gets all of our caps and can ptrace us.
  uint64_t capmask = capdata[0].inheritable;
  capmask |= static_cast<uint64_t>(capdata[1].inheritable) << 32;
  for (unsigned long i = 0; i < 64; ++i) {
    if (capmask & (1ULL << i)) {
      if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, i, 0, 0) != 0) {
        async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                              "failed to raise ambient capability %lu: %s", i, strerror(errno));
      }
    }
  }
}

static pid_t __fork() {
  return clone(nullptr, nullptr, 0, nullptr);
}

// Double-clone, with CLONE_FILES to share the file descriptor table for kcmp validation.
// Returns 0 in the orphaned child, the pid of the orphan in the original process, or -1 on failure.
static void create_vm_process() {
  pid_t first = clone(nullptr, nullptr, CLONE_FILES, nullptr);
  if (first == -1) {
    fatal_errno("failed to clone vm process");
  } else if (first == 0) {
    drop_capabilities();

    if (clone(nullptr, nullptr, CLONE_FILES, nullptr) == -1) {
      _exit(errno);
    }

    // crash_dump is ptracing both sides of the fork; it'll let the parent exit,
    // but keep the orphan stopped to peek at its memory.

    // There appears to be a bug in the kernel where our death causes SIGHUP to
    // be sent to our process group if we exit while it has stopped jobs (e.g.
    // because of wait_for_debugger). Use setsid to create a new process group to
    // avoid hitting this.
    setsid();

    _exit(0);
  }

  int status;
  if (TEMP_FAILURE_RETRY(waitpid(first, &status, __WCLONE)) != first) {
    fatal_errno("failed to waitpid in double fork");
  } else if (!WIFEXITED(status)) {
    fatal("intermediate process didn't exit cleanly in double fork (status = %d)", status);
  } else if (WEXITSTATUS(status)) {
    fatal("second clone failed: %s", strerror(WEXITSTATUS(status)));
  }
}

struct debugger_thread_info {
  pid_t crashing_tid;
  pid_t pseudothread_tid;
  siginfo_t* siginfo;
  void* ucontext;
  debugger_process_info process_info;
};

// Logging and contacting debuggerd requires free file descriptors, which we might not have.
// Work around this by spawning a "thread" that shares its parent's address space, but not its file
// descriptor table, so that we can close random file descriptors without affecting the original
// process. Note that this doesn't go through pthread_create, so TLS is shared with the spawning
// process.
static void* pseudothread_stack;

static DebuggerdDumpType get_dump_type(const debugger_thread_info* thread_info) {
  if (thread_info->siginfo->si_signo == BIONIC_SIGNAL_DEBUGGER &&
      thread_info->siginfo->si_value.sival_int) {
    return kDebuggerdNativeBacktrace;
  }

  return kDebuggerdTombstoneProto;
}

static int debuggerd_dispatch_pseudothread(void* arg) {
  debugger_thread_info* thread_info = static_cast<debugger_thread_info*>(arg);

  for (int i = 0; i < 1024; ++i) {
    // Don't use close to avoid bionic's file descriptor ownership checks.
    syscall(__NR_close, i);
  }

  int devnull = TEMP_FAILURE_RETRY(open("/dev/null", O_RDWR));
  if (devnull == -1) {
    fatal_errno("failed to open /dev/null");
  } else if (devnull != 0) {
    fatal_errno("expected /dev/null fd to be 0, actually %d", devnull);
  }

  // devnull will be 0.
  TEMP_FAILURE_RETRY(dup2(devnull, 1));
  TEMP_FAILURE_RETRY(dup2(devnull, 2));

  unique_fd input_read, input_write;
  unique_fd output_read, output_write;
  if (!Pipe(&input_read, &input_write) != 0 || !Pipe(&output_read, &output_write)) {
    fatal_errno("failed to create pipe");
  }

  uint32_t version;
  ssize_t expected;

  // ucontext_t is absurdly large on AArch64, so piece it together manually with writev.
  struct iovec iovs[4] = {
      {.iov_base = &version, .iov_len = sizeof(version)},
      {.iov_base = thread_info->siginfo, .iov_len = sizeof(siginfo_t)},
      {.iov_base = thread_info->ucontext, .iov_len = sizeof(ucontext_t)},
  };

  if (thread_info->process_info.fdsan_table) {
    // Dynamic executables always use version 4. There is no need to increment the version number if
    // the format changes, because the sender (linker) and receiver (crash_dump) are version locked.
    version = 4;
    expected = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic);

    iovs[3] = {.iov_base = &thread_info->process_info,
               .iov_len = sizeof(thread_info->process_info)};
  } else {
    // Static executables always use version 1.
    version = 1;
    expected = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic);

    iovs[3] = {.iov_base = &thread_info->process_info.abort_msg, .iov_len = sizeof(uintptr_t)};
  }
  errno = 0;
  if (fcntl(output_write.get(), F_SETPIPE_SZ, expected) < static_cast<int>(expected)) {
    fatal_errno("failed to set pipe buffer size");
  }

  ssize_t rc = TEMP_FAILURE_RETRY(writev(output_write.get(), iovs, arraysize(iovs)));
  if (rc == -1) {
    fatal_errno("failed to write crash info");
  } else if (rc != expected) {
    fatal("failed to write crash info, wrote %zd bytes, expected %zd", rc, expected);
  }

  // Don't use fork(2) to avoid calling pthread_atfork handlers.
  pid_t crash_dump_pid = __fork();
  if (crash_dump_pid == -1) {
    async_safe_format_log(ANDROID_LOG_FATAL, "libc",
                          "failed to fork in debuggerd signal handler: %s", strerror(errno));
  } else if (crash_dump_pid == 0) {
    TEMP_FAILURE_RETRY(dup2(input_write.get(), STDOUT_FILENO));
    TEMP_FAILURE_RETRY(dup2(output_read.get(), STDIN_FILENO));
    input_read.reset();
    input_write.reset();
    output_read.reset();
    output_write.reset();

    raise_caps();

    char main_tid[10];
    char pseudothread_tid[10];
    char debuggerd_dump_type[10];
    async_safe_format_buffer(main_tid, sizeof(main_tid), "%d", thread_info->crashing_tid);
    async_safe_format_buffer(pseudothread_tid, sizeof(pseudothread_tid), "%d",
                             thread_info->pseudothread_tid);
    async_safe_format_buffer(debuggerd_dump_type, sizeof(debuggerd_dump_type), "%d",
                             get_dump_type(thread_info));

    execle(CRASH_DUMP_PATH, CRASH_DUMP_NAME, main_tid, pseudothread_tid, debuggerd_dump_type,
           nullptr, nullptr);
    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "failed to exec crash_dump helper: %s",
                          strerror(errno));
    return 1;
  }

  input_write.reset();
  output_read.reset();

  // crash_dump will ptrace and pause all of our threads, and then write to the pipe to tell
  // us to fork off a process to read memory from.
  char buf[4];
  rc = TEMP_FAILURE_RETRY(read(input_read.get(), &buf, sizeof(buf)));

  bool success = false;
  if (rc == 1 && buf[0] == '\1') {
    // crash_dump successfully started, and is ptracing us.
    // Fork off a copy of our address space for it to use.
    create_vm_process();
    success = true;
  } else {
    // Something went wrong, log it.
    if (rc == -1) {
      async_safe_format_log(ANDROID_LOG_FATAL, "libc", "read of IPC pipe failed: %s",
                            strerror(errno));
    } else if (rc == 0) {
      async_safe_format_log(ANDROID_LOG_FATAL, "libc",
                            "crash_dump helper failed to exec, or was killed");
    } else if (rc != 1) {
      async_safe_format_log(ANDROID_LOG_FATAL, "libc",
                            "read of IPC pipe returned unexpected value: %zd", rc);
    } else if (buf[0] != '\1') {
      async_safe_format_log(ANDROID_LOG_FATAL, "libc", "crash_dump helper reported failure");
    }
  }

  // Don't leave a zombie child.
  int status;
  if (TEMP_FAILURE_RETRY(waitpid(crash_dump_pid, &status, 0)) == -1) {
    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "failed to wait for crash_dump helper: %s",
                          strerror(errno));
  } else if (WIFSTOPPED(status) || WIFSIGNALED(status)) {
    async_safe_format_log(ANDROID_LOG_FATAL, "libc", "crash_dump helper crashed or stopped");
  }

  if (success) {
    if (thread_info->siginfo->si_signo != BIONIC_SIGNAL_DEBUGGER) {
      // For crashes, we don't need to minimize pause latency.
      // Wait for the dump to complete before having the process exit, to avoid being murdered by
      // ActivityManager or init.
      TEMP_FAILURE_RETRY(read(input_read, &buf, sizeof(buf)));
    }
  }

  return success ? 0 : 1;
}

static void resend_signal(siginfo_t* info) {
  // Signals can either be fatal or nonfatal.
  // For fatal signals, crash_dump will send us the signal we crashed with
  // before resuming us, so that processes using waitpid on us will see that we
  // exited with the correct exit status (e.g. so that sh will report
  // "Segmentation fault" instead of "Killed"). For this to work, we need
  // to deregister our signal handler for that signal before continuing.
  if (info->si_signo != BIONIC_SIGNAL_DEBUGGER) {
    signal(info->si_signo, SIG_DFL);
    int rc = syscall(SYS_rt_tgsigqueueinfo, __getpid(), __gettid(), info->si_signo, info);
    if (rc != 0) {
      fatal_errno("failed to resend signal during crash");
    }
  }
}

// Handler that does crash dumping by forking and doing the processing in the child.
// Do this by ptracing the relevant thread, and then execing debuggerd to do the actual dump.
static void debuggerd_signal_handler(int signal_number, siginfo_t* info, void* context) {
  // Make sure we don't change the value of errno, in case a signal comes in between the process
  // making a syscall and checking errno.
  ErrnoRestorer restorer;

  auto *ucontext = static_cast<ucontext_t*>(context);

  // It's possible somebody cleared the SA_SIGINFO flag, which would mean
  // our "info" arg holds an undefined value.
  if (!have_siginfo(signal_number)) {
    info = nullptr;
  }

  struct siginfo dummy_info = {};
  if (!info) {
    memset(&dummy_info, 0, sizeof(dummy_info));
    dummy_info.si_signo = signal_number;
    dummy_info.si_code = SI_USER;
    dummy_info.si_pid = __getpid();
    dummy_info.si_uid = getuid();
    info = &dummy_info;
  } else if (info->si_code >= 0 || info->si_code == SI_TKILL) {
    // rt_tgsigqueueinfo(2)'s documentation appears to be incorrect on kernels
    // that contain commit 66dd34a (3.9+). The manpage claims to only allow
    // negative si_code values that are not SI_TKILL, but 66dd34a changed the
    // check to allow all si_code values in calls coming from inside the house.
  }

  debugger_process_info process_info = {};
  uintptr_t si_val = reinterpret_cast<uintptr_t>(info->si_ptr);
  if (signal_number == BIONIC_SIGNAL_DEBUGGER) {
    if (info->si_code == SI_QUEUE && info->si_pid == __getpid()) {
      // Allow for the abort message to be explicitly specified via the sigqueue value.
      // Keep the bottom bit intact for representing whether we want a backtrace or a tombstone.
      if (si_val != kDebuggerdFallbackSivalUintptrRequestDump) {
        process_info.abort_msg = reinterpret_cast<void*>(si_val & ~1);
        info->si_ptr = reinterpret_cast<void*>(si_val & 1);
      }
    }
  } else if (g_callbacks.get_process_info) {
    process_info = g_callbacks.get_process_info();
  }

  // If sival_int is ~0, it means that the fallback handler has been called
  // once before and this function is being called again to dump the stack
  // of a specific thread. It is possible that the prctl call might return 1,
  // then return 0 in subsequent calls, so check the sival_int to determine if
  // the fallback handler should be called first.
  if (si_val == kDebuggerdFallbackSivalUintptrRequestDump ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1) {
    // This check might be racy if another thread sets NO_NEW_PRIVS, but this should be unlikely,
    // you can only set NO_NEW_PRIVS to 1, and the effect should be at worst a single missing
    // ANR trace.
    debuggerd_fallback_handler(info, ucontext, process_info.abort_msg);
    resend_signal(info);
    return;
  }

  // Only allow one thread to handle a signal at a time.
  int ret = pthread_mutex_lock(&crash_mutex);
  if (ret != 0) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc", "pthread_mutex_lock failed: %s", strerror(ret));
    return;
  }

  log_signal_summary(info);

  debugger_thread_info thread_info = {
      .crashing_tid = __gettid(),
      .pseudothread_tid = -1,
      .siginfo = info,
      .ucontext = context,
      .process_info = process_info,
  };

  // Set PR_SET_DUMPABLE to 1, so that crash_dump can ptrace us.
  int orig_dumpable = prctl(PR_GET_DUMPABLE);
  if (prctl(PR_SET_DUMPABLE, 1) != 0) {
    fatal_errno("failed to set dumpable");
  }

  // On kernels with yama_ptrace enabled, also allow any process to attach.
  bool restore_orig_ptracer = true;
  if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) != 0) {
    if (errno == EINVAL) {
      // This kernel does not support PR_SET_PTRACER_ANY, or Yama is not enabled.
      restore_orig_ptracer = false;
    } else {
      fatal_errno("failed to set traceable");
    }
  }

  // Essentially pthread_create without CLONE_FILES, so we still work during file descriptor
  // exhaustion.
  pid_t child_pid =
    clone(debuggerd_dispatch_pseudothread, pseudothread_stack,
          CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID,
          &thread_info, nullptr, nullptr, &thread_info.pseudothread_tid);
  if (child_pid == -1) {
    fatal_errno("failed to spawn debuggerd dispatch thread");
  }

  // Wait for the child to start...
  futex_wait(&thread_info.pseudothread_tid, -1);

  // and then wait for it to terminate.
  futex_wait(&thread_info.pseudothread_tid, child_pid);

  // Restore PR_SET_DUMPABLE to its original value.
  if (prctl(PR_SET_DUMPABLE, orig_dumpable) != 0) {
    fatal_errno("failed to restore dumpable");
  }

  // Restore PR_SET_PTRACER to its original value.
  if (restore_orig_ptracer && prctl(PR_SET_PTRACER, 0) != 0) {
    fatal_errno("failed to restore traceable");
  }

  if (info->si_signo == BIONIC_SIGNAL_DEBUGGER) {
    // If the signal is fatal, don't unlock the mutex to prevent other crashing threads from
    // starting to dump right before our death.
    pthread_mutex_unlock(&crash_mutex);
  } else {
    // Resend the signal, so that either the debugger or the parent's waitpid sees it.
    resend_signal(info);
  }
}

void debuggerd_init(debuggerd_callbacks_t* callbacks) {
  if (callbacks) {
    g_callbacks = *callbacks;
  }

  size_t thread_stack_pages = 8;
  void* thread_stack_allocation = mmap(nullptr, PAGE_SIZE * (thread_stack_pages + 2), PROT_NONE,
                                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (thread_stack_allocation == MAP_FAILED) {
    fatal_errno("failed to allocate debuggerd thread stack");
  }

  char* stack = static_cast<char*>(thread_stack_allocation) + PAGE_SIZE;
  if (mprotect(stack, PAGE_SIZE * thread_stack_pages, PROT_READ | PROT_WRITE) != 0) {
    fatal_errno("failed to mprotect debuggerd thread stack");
  }

  // Stack grows negatively, set it to the last byte in the page...
  stack = (stack + thread_stack_pages * PAGE_SIZE - 1);
  // and align it.
  stack -= 15;
  pseudothread_stack = stack;

  struct sigaction action;
  memset(&action, 0, sizeof(action));
  sigfillset(&action.sa_mask);
  action.sa_sigaction = debuggerd_signal_handler;
  action.sa_flags = SA_RESTART | SA_SIGINFO;

  // Use the alternate signal stack if available so we can catch stack overflows.
  action.sa_flags |= SA_ONSTACK;

#define SA_EXPOSE_TAGBITS 0x00000800
  // Request that the kernel set tag bits in the fault address. This is necessary for diagnosing MTE
  // faults.
  action.sa_flags |= SA_EXPOSE_TAGBITS;

  debuggerd_register_handlers(&action);
}
