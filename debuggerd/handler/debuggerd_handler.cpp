/*
 * Copyright 2008 The Android Open Source Project
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

#include "debuggerd/handler.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
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
#include <android-base/parsebool.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <async_safe/log.h>
#include <bionic/reserved_signals.h>

#include <libdebuggerd/utility.h>

#include "dump_type.h"
#include "protocol.h"

#include "handler/fallback.h"

using ::android::base::ParseBool;
using ::android::base::ParseBoolResult;
using ::android::base::Pipe;

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

static bool property_parse_bool(const char* name) {
  const prop_info* pi = __system_property_find(name);
  if (!pi) return false;
  bool cookie = false;
  __system_property_read_callback(
      pi,
      [](void* cookie, const char*, const char* value, uint32_t) {
        *reinterpret_cast<bool*>(cookie) = ParseBool(value) == ParseBoolResult::kTrue;
      },
      &cookie);
  return cookie;
}

static bool is_permissive_mte() {
  // Environment variable for testing or local use from shell.
  char* permissive_env = getenv("MTE_PERMISSIVE");
  char process_sysprop_name[512];
  async_safe_format_buffer(process_sysprop_name, sizeof(process_sysprop_name),
                           "persist.device_config.memory_safety_native.permissive.process.%s",
                           getprogname());
  // DO NOT REPLACE this with GetBoolProperty. That uses std::string which allocates, so it is
  // not async-safe (and this functiong gets used in a signal handler).
  return property_parse_bool("persist.sys.mte.permissive") ||
         property_parse_bool("persist.device_config.memory_safety_native.permissive.default") ||
         property_parse_bool(process_sysprop_name) ||
         (permissive_env && ParseBool(permissive_env) == ParseBoolResult::kTrue);
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
static void log_signal_summary(const siginfo_t* si) {
  char main_thread_name[MAX_TASK_NAME_LEN + 1];
  if (!get_main_thread_name(main_thread_name, sizeof(main_thread_name))) {
    strncpy(main_thread_name, "<unknown>", sizeof(main_thread_name));
  }

  if (si->si_signo == BIONIC_SIGNAL_DEBUGGER) {
    async_safe_format_log(ANDROID_LOG_INFO, "libc", "Requested dump for pid %d (%s)", __getpid(),
                          main_thread_name);
    return;
  }

  // Many signals don't have a sender or extra detail, but some do...
  pid_t self_pid = __getpid();
  char sender_desc[32] = {};  // " from pid 1234, uid 666"
  if (signal_has_sender(si, self_pid)) {
    get_signal_sender(sender_desc, sizeof(sender_desc), si);
  }
  char extra_desc[32] = {};  // ", fault addr 0x1234" or ", syscall 1234"
  if (si->si_signo == SIGSYS && si->si_code == SYS_SECCOMP) {
    async_safe_format_buffer(extra_desc, sizeof(extra_desc), ", syscall %d", si->si_syscall);
  } else if (signal_has_si_addr(si)) {
    async_safe_format_buffer(extra_desc, sizeof(extra_desc), ", fault addr %p", si->si_addr);
  }

  char thread_name[MAX_TASK_NAME_LEN + 1];  // one more for termination
  if (prctl(PR_GET_NAME, reinterpret_cast<unsigned long>(thread_name), 0, 0, 0) != 0) {
    strcpy(thread_name, "<name unknown>");
  } else {
    // short names are null terminated by prctl, but the man page
    // implies that 16 byte names are not.
    thread_name[MAX_TASK_NAME_LEN] = 0;
  }

  async_safe_format_log(ANDROID_LOG_FATAL, "libc",
                        "Fatal signal %d (%s), code %d (%s%s)%s in tid %d (%s), pid %d (%s)",
                        si->si_signo, get_signame(si), si->si_code, get_sigcode(si), sender_desc,
                        extra_desc, __gettid(), thread_name, self_pid, main_thread_name);
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

  constexpr size_t kHeaderSize = sizeof(version) + sizeof(siginfo_t) + sizeof(ucontext_t);

  if (thread_info->process_info.fdsan_table) {
    // Dynamic executables always use version 4. There is no need to increment the version number if
    // the format changes, because the sender (linker) and receiver (crash_dump) are version locked.
    version = 4;
    expected = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic);

    static_assert(sizeof(CrashInfoHeader) + sizeof(CrashInfoDataDynamic) ==
                      kHeaderSize + sizeof(thread_info->process_info),
                  "Wire protocol structs do not match the data sent.");
#define ASSERT_SAME_OFFSET(MEMBER1, MEMBER2) \
    static_assert(sizeof(CrashInfoHeader) + offsetof(CrashInfoDataDynamic, MEMBER1) == \
                      kHeaderSize + offsetof(debugger_process_info, MEMBER2), \
                  "Wire protocol offset does not match data sent: " #MEMBER1);
    ASSERT_SAME_OFFSET(fdsan_table_address, fdsan_table);
    ASSERT_SAME_OFFSET(gwp_asan_state, gwp_asan_state);
    ASSERT_SAME_OFFSET(gwp_asan_metadata, gwp_asan_metadata);
    ASSERT_SAME_OFFSET(scudo_stack_depot, scudo_stack_depot);
    ASSERT_SAME_OFFSET(scudo_region_info, scudo_region_info);
    ASSERT_SAME_OFFSET(scudo_ring_buffer, scudo_ring_buffer);
    ASSERT_SAME_OFFSET(scudo_ring_buffer_size, scudo_ring_buffer_size);
    ASSERT_SAME_OFFSET(scudo_stack_depot_size, scudo_stack_depot_size);
    ASSERT_SAME_OFFSET(recoverable_crash, recoverable_crash);
    ASSERT_SAME_OFFSET(crash_detail_page, crash_detail_page);
#undef ASSERT_SAME_OFFSET

    iovs[3] = {.iov_base = &thread_info->process_info,
               .iov_len = sizeof(thread_info->process_info)};
  } else {
    // Static executables always use version 1.
    version = 1;
    expected = sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic);

    static_assert(
        sizeof(CrashInfoHeader) + sizeof(CrashInfoDataStatic) == kHeaderSize + sizeof(uintptr_t),
        "Wire protocol structs do not match the data sent.");

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
  if (g_callbacks.get_process_info) {
    process_info = g_callbacks.get_process_info();
  }
  uintptr_t si_val = reinterpret_cast<uintptr_t>(info->si_ptr);
  if (signal_number == BIONIC_SIGNAL_DEBUGGER) {
    // Applications can set abort messages via android_set_abort_message without
    // actually aborting; ignore those messages in non-fatal dumps.
    process_info.abort_msg = nullptr;
    if (info->si_code == SI_QUEUE && info->si_pid == __getpid()) {
      // Allow for the abort message to be explicitly specified via the sigqueue value.
      // Keep the bottom bit intact for representing whether we want a backtrace or a tombstone.
      if (si_val != kDebuggerdFallbackSivalUintptrRequestDump) {
        process_info.abort_msg = reinterpret_cast<void*>(si_val & ~1);
        info->si_ptr = reinterpret_cast<void*>(si_val & 1);
      }
    }
  }

  gwp_asan_callbacks_t gwp_asan_callbacks = {};
  bool recoverable_gwp_asan_crash = false;
  if (g_callbacks.get_gwp_asan_callbacks != nullptr) {
    // GWP-ASan catches use-after-free and heap-buffer-overflow by using PROT_NONE
    // guard pages, which lead to SEGV. Normally, debuggerd prints a bug report
    // and the process terminates, but in some cases, we actually want to print
    // the bug report and let the signal handler return, and restart the process.
    // In order to do that, we need to disable GWP-ASan's guard pages. The
    // following callbacks handle this case.
    gwp_asan_callbacks = g_callbacks.get_gwp_asan_callbacks();
    if (signal_number == SIGSEGV && signal_has_si_addr(info) &&
        gwp_asan_callbacks.debuggerd_needs_gwp_asan_recovery &&
        gwp_asan_callbacks.debuggerd_gwp_asan_pre_crash_report &&
        gwp_asan_callbacks.debuggerd_gwp_asan_post_crash_report &&
        gwp_asan_callbacks.debuggerd_needs_gwp_asan_recovery(info->si_addr)) {
      gwp_asan_callbacks.debuggerd_gwp_asan_pre_crash_report(info->si_addr);
      recoverable_gwp_asan_crash = true;
      process_info.recoverable_crash = true;
    }
  }

  if (info->si_signo == SIGSEGV &&
      (info->si_code == SEGV_MTESERR || info->si_code == SEGV_MTEAERR) && is_permissive_mte()) {
    process_info.recoverable_crash = true;
    // If we are in permissive MTE mode, we do not crash, but instead disable MTE on this thread,
    // and then let the failing instruction be retried. The second time should work (except
    // if there is another non-MTE fault).
    int tagged_addr_ctrl = prctl(PR_GET_TAGGED_ADDR_CTRL, 0, 0, 0, 0);
    if (tagged_addr_ctrl < 0) {
      fatal_errno("failed to PR_GET_TAGGED_ADDR_CTRL");
    }
    tagged_addr_ctrl = (tagged_addr_ctrl & ~PR_MTE_TCF_MASK) | PR_MTE_TCF_NONE;
    if (prctl(PR_SET_TAGGED_ADDR_CTRL, tagged_addr_ctrl, 0, 0, 0) < 0) {
      fatal_errno("failed to PR_SET_TAGGED_ADDR_CTRL");
    }
    async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                          "MTE ERROR DETECTED BUT RUNNING IN PERMISSIVE MODE. CONTINUING.");
    pthread_mutex_unlock(&crash_mutex);
  }

  // If sival_int is ~0, it means that the fallback handler has been called
  // once before and this function is being called again to dump the stack
  // of a specific thread. It is possible that the prctl call might return 1,
  // then return 0 in subsequent calls, so check the sival_int to determine if
  // the fallback handler should be called first.
  bool no_new_privs = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1;
  if (si_val == kDebuggerdFallbackSivalUintptrRequestDump || no_new_privs) {
    // This check might be racy if another thread sets NO_NEW_PRIVS, but this should be unlikely,
    // you can only set NO_NEW_PRIVS to 1, and the effect should be at worst a single missing
    // ANR trace.
    debuggerd_fallback_handler(info, ucontext, process_info.abort_msg);
    if (no_new_privs && recoverable_gwp_asan_crash) {
      gwp_asan_callbacks.debuggerd_gwp_asan_post_crash_report(info->si_addr);
      return;
    }
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

  // If we got here due to the signal BIONIC_SIGNAL_DEBUGGER, it's possible
  // this is not the main thread, which can cause the intercept logic to fail
  // since the intercept is only looking for the main thread. In this case,
  // setting crashing_tid to pid instead of the current thread's tid avoids
  // the problem.
  debugger_thread_info thread_info = {
      .crashing_tid = (signal_number == BIONIC_SIGNAL_DEBUGGER) ? __getpid() : __gettid(),
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
  } else if (process_info.recoverable_crash) {
    if (recoverable_gwp_asan_crash) {
      gwp_asan_callbacks.debuggerd_gwp_asan_post_crash_report(info->si_addr);
    }
    pthread_mutex_unlock(&crash_mutex);
  }
#ifdef __aarch64__
  else if (info->si_signo == SIGSEGV && info->si_code == SEGV_MTEAERR && getppid() == 1) {
    // Back channel to init (see system/core/init/service.cpp) to signal that
    // this process crashed due to an ASYNC MTE fault and should be considered
    // for upgrade to SYNC mode. We are re-using the ART profiler signal, which
    // is always handled (ignored in native processes, handled for generating a
    // dump in ART processes), so a process will never crash from this signal
    // except from here.
    // The kernel is not particularly receptive to adding this information:
    // https://lore.kernel.org/all/20220909180617.374238-1-fmayer@google.com/, so we work around
    // like this.
    info->si_signo = BIONIC_SIGNAL_ART_PROFILER;
    resend_signal(info);
  }
#endif
  else {
    // Resend the signal, so that either the debugger or the parent's waitpid sees it.
    resend_signal(info);
  }
}

void debuggerd_init(debuggerd_callbacks_t* callbacks) {
  if (callbacks) {
    g_callbacks = *callbacks;
  }

  size_t thread_stack_pages = 8;
  void* thread_stack_allocation = mmap(nullptr, getpagesize() * (thread_stack_pages + 2), PROT_NONE,
                                       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (thread_stack_allocation == MAP_FAILED) {
    fatal_errno("failed to allocate debuggerd thread stack");
  }

  char* stack = static_cast<char*>(thread_stack_allocation) + getpagesize();
  if (mprotect(stack, getpagesize() * thread_stack_pages, PROT_READ | PROT_WRITE) != 0) {
    fatal_errno("failed to mprotect debuggerd thread stack");
  }

  // Stack grows negatively, set it to the last byte in the page...
  stack = (stack + thread_stack_pages * getpagesize() - 1);
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

bool debuggerd_handle_gwp_asan_signal(int signal_number, siginfo_t* info, void* context) {
  if (g_callbacks.get_gwp_asan_callbacks == nullptr) return false;
  gwp_asan_callbacks_t gwp_asan_callbacks = g_callbacks.get_gwp_asan_callbacks();
  if (gwp_asan_callbacks.debuggerd_needs_gwp_asan_recovery == nullptr ||
      gwp_asan_callbacks.debuggerd_gwp_asan_pre_crash_report == nullptr ||
      gwp_asan_callbacks.debuggerd_gwp_asan_post_crash_report == nullptr ||
      !gwp_asan_callbacks.debuggerd_needs_gwp_asan_recovery(info->si_addr)) {
    return false;
  }

  // Only dump a crash report for the first GWP-ASan crash. ActivityManager
  // doesn't like it when an app crashes multiple times, and is even more strict
  // about an app crashing multiple times in a short time period. While the app
  // won't crash fully when we do GWP-ASan recovery, ActivityManager still gets
  // the information about the crash through the DropBoxManager service. If an
  // app has multiple back-to-back GWP-ASan crashes, this would lead to the app
  // being killed, which defeats the purpose of having the recoverable mode. To
  // mitigate against this, only generate a debuggerd crash report for the first
  // GWP-ASan crash encountered. We still need to do the patching up of the
  // allocator though, so do that.
  static pthread_mutex_t first_crash_mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&first_crash_mutex);
  static bool first_crash = true;

  if (first_crash) {
    // `debuggerd_signal_handler` will call
    // `debuggerd_gwp_asan_(pre|post)_crash_report`, so no need to manually call
    // them here.
    debuggerd_signal_handler(signal_number, info, context);
    first_crash = false;
  } else {
    gwp_asan_callbacks.debuggerd_gwp_asan_pre_crash_report(info->si_addr);
    gwp_asan_callbacks.debuggerd_gwp_asan_post_crash_report(info->si_addr);
  }

  pthread_mutex_unlock(&first_crash_mutex);
  return true;
}

// When debuggerd's signal handler is the first handler called, it's great at
// handling the recoverable GWP-ASan and permissive MTE modes. For apps,
// sigchain (from libart) is always the first signal handler, and so the
// following function is what sigchain must call before processing the signal.
// This allows for processing of a potentially recoverable GWP-ASan or MTE
// crash. If the signal requires recovery, then dump a report (via the regular
// debuggerd hanndler), and patch up the allocator (in the case of GWP-ASan) or
// disable MTE on the thread, and allow the process to continue (indicated by
// returning 'true'). If the crash has nothing to do with GWP-ASan/MTE, or
// recovery isn't possible, return 'false'.
bool debuggerd_handle_signal(int signal_number, siginfo_t* info, void* context) {
  if (signal_number != SIGSEGV) return false;
  if (info->si_code == SEGV_MTEAERR || info->si_code == SEGV_MTESERR) {
    if (!is_permissive_mte()) return false;
    // Because permissive MTE disables MTE for the entire thread, we're less
    // worried about getting a whole bunch of crashes in a row. ActivityManager
    // doesn't like multiple native crashes for an app in a short period of time
    // (see the comment about recoverable GWP-ASan in
    // `debuggerd_handle_gwp_asan_signal`), but that shouldn't happen if MTE is
    // disabled for the entire thread. This might need to be changed if there's
    // some low-hanging bug that happens across multiple threads in quick
    // succession.
    debuggerd_signal_handler(signal_number, info, context);
    return true;
  }

  if (!signal_has_si_addr(info)) return false;
  return debuggerd_handle_gwp_asan_signal(signal_number, info, context);
}
