/*
 * Copyright 2016, The Android Open Source Project
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
#include <dlfcn.h>
#include <err.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/prctl.h>
#include <malloc.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdlib.h>
#include <sys/capability.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <chrono>
#include <regex>
#include <set>
#include <string>
#include <thread>

#include <android/crash_detail.h>
#include <android/dlext.h>
#include <android/fdsan.h>
#include <android/set_abort_message.h>
#include <bionic/malloc.h>
#include <bionic/mte.h>
#include <bionic/reserved_signals.h>

#include <android-base/cmsg.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <unwindstack/Elf.h>
#include <unwindstack/Memory.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include "crash_test.h"
#include "debuggerd/handler.h"
#include "gtest/gtest.h"
#include "libdebuggerd/utility_host.h"
#include "protocol.h"
#include "tombstoned/tombstoned.h"
#include "util.h"

using namespace std::chrono_literals;

using android::base::SendFileDescriptors;
using android::base::unique_fd;
using ::testing::HasSubstr;

#if defined(__LP64__)
#define ARCH_SUFFIX "64"
#else
#define ARCH_SUFFIX ""
#endif

constexpr char kWaitForDebuggerKey[] = "debug.debuggerd.wait_for_debugger";

#define TIMEOUT(seconds, expr)                                     \
  [&]() {                                                          \
    struct sigaction old_sigaction;                                \
    struct sigaction new_sigaction = {};                           \
    new_sigaction.sa_handler = [](int) {};                         \
    if (sigaction(SIGALRM, &new_sigaction, &old_sigaction) != 0) { \
      err(1, "sigaction failed");                                  \
    }                                                              \
    alarm(seconds * android::base::HwTimeoutMultiplier());         \
    auto value = expr;                                             \
    int saved_errno = errno;                                       \
    if (sigaction(SIGALRM, &old_sigaction, nullptr) != 0) {        \
      err(1, "sigaction failed");                                  \
    }                                                              \
    alarm(0);                                                      \
    errno = saved_errno;                                           \
    return value;                                                  \
  }()

// Backtrace frame dump could contain:
//   #01 pc 0001cded  /data/tmp/debuggerd_test32 (raise_debugger_signal+80)
// or
//   #01 pc 00022a09  /data/tmp/debuggerd_test32 (offset 0x12000) (raise_debugger_signal+80)
#define ASSERT_BACKTRACE_FRAME(result, frame_name) \
  ASSERT_MATCH(result,                             \
               R"(#\d\d pc [0-9a-f]+\s+ \S+ (\(offset 0x[0-9a-f]+\) )?\()" frame_name R"(\+)");

static void tombstoned_intercept(pid_t target_pid, unique_fd* intercept_fd, unique_fd* output_fd,
                                 InterceptResponse* response, DebuggerdDumpType intercept_type) {
  intercept_fd->reset(socket_local_client(kTombstonedInterceptSocketName,
                                          ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (intercept_fd->get() == -1) {
    FAIL() << "failed to contact tombstoned: " << strerror(errno);
  }

  InterceptRequest req = {
      .dump_type = intercept_type,
      .pid = target_pid,
  };

  unique_fd output_pipe_write;
  if (!Pipe(output_fd, &output_pipe_write)) {
    FAIL() << "failed to create output pipe: " << strerror(errno);
  }

  std::string pipe_size_str;
  int pipe_buffer_size;
  if (!android::base::ReadFileToString("/proc/sys/fs/pipe-max-size", &pipe_size_str)) {
    FAIL() << "failed to read /proc/sys/fs/pipe-max-size: " << strerror(errno);
  }

  pipe_size_str = android::base::Trim(pipe_size_str);

  if (!android::base::ParseInt(pipe_size_str.c_str(), &pipe_buffer_size, 0)) {
    FAIL() << "failed to parse pipe max size";
  }

  if (fcntl(output_fd->get(), F_SETPIPE_SZ, pipe_buffer_size) != pipe_buffer_size) {
    FAIL() << "failed to set pipe size: " << strerror(errno);
  }

  ASSERT_GE(pipe_buffer_size, 1024 * 1024);

  ssize_t rc = SendFileDescriptors(intercept_fd->get(), &req, sizeof(req), output_pipe_write.get());
  output_pipe_write.reset();
  if (rc != sizeof(req)) {
    FAIL() << "failed to send output fd to tombstoned: " << strerror(errno);
  }

  rc = TEMP_FAILURE_RETRY(read(intercept_fd->get(), response, sizeof(*response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "failed to read response from tombstoned (EOF)";
  } else if (rc != sizeof(*response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(*response)
           << ", received " << rc;
  }
}

static bool pac_supported() {
#if defined(__aarch64__)
  return getauxval(AT_HWCAP) & HWCAP_PACA;
#else
  return false;
#endif
}

class CrasherTest : public ::testing::Test {
 public:
  pid_t crasher_pid = -1;
  bool previous_wait_for_debugger;
  unique_fd crasher_pipe;
  unique_fd intercept_fd;

  CrasherTest();
  ~CrasherTest();

  void StartIntercept(unique_fd* output_fd, DebuggerdDumpType intercept_type = kDebuggerdTombstone);

  // Returns -1 if we fail to read a response from tombstoned, otherwise the received return code.
  void FinishIntercept(int* result);

  void StartProcess(std::function<void()> function, std::function<pid_t()> forker = fork);
  void StartCrasher(const std::string& crash_type);
  void FinishCrasher();
  void AssertDeath(int signo);

  static void Trap(void* ptr);
};

CrasherTest::CrasherTest() {
  previous_wait_for_debugger = android::base::GetBoolProperty(kWaitForDebuggerKey, false);
  android::base::SetProperty(kWaitForDebuggerKey, "0");

  // Clear the old property too, just in case someone's been using it
  // on this device. (We only document the new name, but we still support
  // the old name so we don't break anyone's existing setups.)
  android::base::SetProperty("debug.debuggerd.wait_for_gdb", "0");
}

CrasherTest::~CrasherTest() {
  if (crasher_pid != -1) {
    kill(crasher_pid, SIGKILL);
    int status;
    TEMP_FAILURE_RETRY(waitpid(crasher_pid, &status, WUNTRACED));
  }

  android::base::SetProperty(kWaitForDebuggerKey, previous_wait_for_debugger ? "1" : "0");
}

void CrasherTest::StartIntercept(unique_fd* output_fd, DebuggerdDumpType intercept_type) {
  if (crasher_pid == -1) {
    FAIL() << "crasher hasn't been started";
  }

  InterceptResponse response = {};
  tombstoned_intercept(crasher_pid, &this->intercept_fd, output_fd, &response, intercept_type);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;
}

void CrasherTest::FinishIntercept(int* result) {
  InterceptResponse response;

  ssize_t rc = TIMEOUT(30, read(intercept_fd.get(), &response, sizeof(response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    *result = -1;
  } else if (rc != sizeof(response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
           << ", received " << rc;
  } else {
    *result = response.status == InterceptStatus::kStarted ? 1 : 0;
  }
}

void CrasherTest::StartProcess(std::function<void()> function, std::function<pid_t()> forker) {
  unique_fd read_pipe;
  unique_fd crasher_read_pipe;
  if (!Pipe(&crasher_read_pipe, &crasher_pipe)) {
    FAIL() << "failed to create pipe: " << strerror(errno);
  }

  crasher_pid = forker();
  if (crasher_pid == -1) {
    FAIL() << "fork failed: " << strerror(errno);
  } else if (crasher_pid == 0) {
    char dummy;
    crasher_pipe.reset();
    TEMP_FAILURE_RETRY(read(crasher_read_pipe.get(), &dummy, 1));
    function();
    _exit(0);
  }
}

void CrasherTest::FinishCrasher() {
  if (crasher_pipe == -1) {
    FAIL() << "crasher pipe uninitialized";
  }

  ssize_t rc = TEMP_FAILURE_RETRY(write(crasher_pipe.get(), "\n", 1));
  if (rc == -1) {
    FAIL() << "failed to write to crasher pipe: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "crasher pipe was closed";
  }
}

void CrasherTest::AssertDeath(int signo) {
  int status;
  pid_t pid = TIMEOUT(30, waitpid(crasher_pid, &status, 0));
  if (pid != crasher_pid) {
    printf("failed to wait for crasher (expected pid %d, return value %d): %s\n", crasher_pid, pid,
           strerror(errno));
    sleep(100);
    FAIL() << "failed to wait for crasher: " << strerror(errno);
  }

  if (signo == 0) {
    ASSERT_TRUE(WIFEXITED(status)) << "Terminated due to unexpected signal " << WTERMSIG(status);
    ASSERT_EQ(0, WEXITSTATUS(signo));
  } else {
    ASSERT_FALSE(WIFEXITED(status));
    ASSERT_TRUE(WIFSIGNALED(status)) << "crasher didn't terminate via a signal";
    ASSERT_EQ(signo, WTERMSIG(status));
  }
  crasher_pid = -1;
}

static void ConsumeFd(unique_fd fd, std::string* output) {
  ASSERT_TRUE(android::base::ReadFdToString(fd, output));
}

class LogcatCollector {
 public:
  LogcatCollector() { system("logcat -c"); }

  void Collect(std::string* output) {
    FILE* cmd_stdout = popen("logcat -d '*:S DEBUG'", "r");
    ASSERT_NE(cmd_stdout, nullptr);
    unique_fd tmp_fd(TEMP_FAILURE_RETRY(dup(fileno(cmd_stdout))));
    ConsumeFd(std::move(tmp_fd), output);
    pclose(cmd_stdout);
  }
};

TEST_F(CrasherTest, smoke) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    *reinterpret_cast<volatile char*>(0xdead) = '1';
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0+dead)");

  if (mte_supported() && mte_enabled()) {
    // Test that the default TAGGED_ADDR_CTRL value is set.
    ASSERT_MATCH(result, R"(tagged_addr_ctrl: 000000000007fff3)"
                         R"( \(PR_TAGGED_ADDR_ENABLE, PR_MTE_TCF_SYNC, mask 0xfffe\))");
  }

  if (pac_supported()) {
    // Test that the default PAC_ENABLED_KEYS value is set.
    ASSERT_MATCH(result, R"(pac_enabled_keys: 000000000000000f)"
                         R"( \(PR_PAC_APIAKEY, PR_PAC_APIBKEY, PR_PAC_APDAKEY, PR_PAC_APDBKEY\))");
  }
}

TEST_F(CrasherTest, tagged_fault_addr) {
#if !defined(__aarch64__)
  GTEST_SKIP() << "Requires aarch64";
#endif
  // HWASan crashes with SIGABRT on tag mismatch.
  SKIP_WITH_HWASAN;
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    *reinterpret_cast<volatile char*>(0x100000000000dead) = '1';
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // The address can either be tagged (new kernels) or untagged (old kernels).
  ASSERT_MATCH(
      result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x[01]00000000000dead)");
}

void CrasherTest::Trap(void* ptr) {
  void (*volatile f)(void*) = nullptr;
  __asm__ __volatile__("" : : "r"(f) : "memory");
  f(ptr);
}

TEST_F(CrasherTest, heap_addr_in_register) {
#if defined(__i386__)
  GTEST_SKIP() << "architecture does not pass arguments in registers";
#endif
  // The memory dump in HWASan crashes sadly shows the memory near the registers
  // in the HWASan dump function, rather the faulting context. This is a known
  // issue.
  SKIP_WITH_HWASAN;
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    // Crash with a heap pointer in the first argument register.
    Trap(malloc(1));
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  int status;
  ASSERT_EQ(crasher_pid, TIMEOUT(30, waitpid(crasher_pid, &status, 0)));
  ASSERT_TRUE(WIFSIGNALED(status)) << "crasher didn't terminate via a signal";
  // Don't test the signal number because different architectures use different signals for
  // __builtin_trap().
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

#if defined(__aarch64__)
  ASSERT_MATCH(result, "memory near x0 \\(\\[anon:");
#elif defined(__arm__)
  ASSERT_MATCH(result, "memory near r0 \\(\\[anon:");
#elif defined(__riscv)
  ASSERT_MATCH(result, "memory near a0 \\(\\[anon:");
#elif defined(__x86_64__)
  ASSERT_MATCH(result, "memory near rdi \\(\\[anon:");
#else
  ASSERT_TRUE(false) << "unsupported architecture";
#endif
}

#if defined(__aarch64__)
static void SetTagCheckingLevelSync() {
  if (mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_SYNC) == 0) {
    abort();
  }
}

static void SetTagCheckingLevelAsync() {
  if (mallopt(M_BIONIC_SET_HEAP_TAGGING_LEVEL, M_HEAP_TAGGING_LEVEL_ASYNC) == 0) {
    abort();
  }
}
#endif

struct SizeParamCrasherTest : CrasherTest, testing::WithParamInterface<size_t> {};

INSTANTIATE_TEST_SUITE_P(Sizes, SizeParamCrasherTest, testing::Values(0, 16, 131072));

TEST_P(SizeParamCrasherTest, mte_uaf) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  // Any UAF on a zero-sized allocation will be out-of-bounds so it won't be reported.
  if (GetParam() == 0) {
    return;
  }

  LogcatCollector logcat_collector;

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    volatile int* p = (volatile int*)malloc(GetParam());
    free((void *)p);
    p[0] = 42;
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::vector<std::string> log_sources(2);
  ConsumeFd(std::move(output_fd), &log_sources[0]);
  logcat_collector.Collect(&log_sources[1]);
  // Tag dump only available in the tombstone, not logcat.
  ASSERT_MATCH(log_sources[0], "Memory tags around the fault address");

  for (const auto& result : log_sources) {
    ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
    ASSERT_MATCH(result, R"(Cause: \[MTE\]: Use After Free, 0 bytes into a )" +
                             std::to_string(GetParam()) + R"(-byte allocation)");
    ASSERT_MATCH(result, R"(deallocated by thread .*?\n.*#00 pc)");
    ASSERT_MATCH(result, R"((^|\s)allocated by thread .*?\n.*#00 pc)");
  }
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_P(SizeParamCrasherTest, mte_oob_uaf) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    volatile int* p = (volatile int*)malloc(GetParam());
    free((void *)p);
    p[-1] = 42;
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
  ASSERT_NOT_MATCH(result, R"(Cause: \[MTE\]: Use After Free, 4 bytes left)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_P(SizeParamCrasherTest, mte_overflow) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  LogcatCollector logcat_collector;
  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    volatile char* p = (volatile char*)malloc(GetParam());
    p[GetParam()] = 42;
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::vector<std::string> log_sources(2);
  ConsumeFd(std::move(output_fd), &log_sources[0]);
  logcat_collector.Collect(&log_sources[1]);

  // Tag dump only in tombstone, not logcat, and tagging is not used for
  // overflow protection in the scudo secondary (guard pages are used instead).
  if (GetParam() < 0x10000) {
    ASSERT_MATCH(log_sources[0], "Memory tags around the fault address");
  }

  for (const auto& result : log_sources) {
    ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
    ASSERT_MATCH(result, R"(Cause: \[MTE\]: Buffer Overflow, 0 bytes right of a )" +
                             std::to_string(GetParam()) + R"(-byte allocation)");
    ASSERT_MATCH(result, R"((^|\s)allocated by thread .*?\n.*#00 pc)");
  }
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_P(SizeParamCrasherTest, mte_underflow) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    volatile int* p = (volatile int*)malloc(GetParam());
    p[-1] = 42;
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 9 \(SEGV_MTESERR\))");
  ASSERT_MATCH(result, R"(Cause: \[MTE\]: Buffer Underflow, 4 bytes left of a )" +
                           std::to_string(GetParam()) + R"(-byte allocation)");
  ASSERT_MATCH(result, R"((^|\s)allocated by thread .*
      #00 pc)");
  ASSERT_MATCH(result, "Memory tags around the fault address");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

__attribute__((noinline)) void mte_illegal_setjmp_helper(jmp_buf& jump_buf) {
  // This frame is at least 8 bytes for storing and restoring the LR before the
  // setjmp below. So this can never get an empty stack frame, even if we omit
  // the frame pointer. So, the SP of this is always less (numerically) than the
  // calling function frame.
  setjmp(jump_buf);
}

TEST_F(CrasherTest, DISABLED_mte_illegal_setjmp) {
  // This setjmp is illegal because it jumps back into a function that already returned.
  // Quoting man 3 setjmp:
  //     If the function which called setjmp() returns before longjmp() is
  //     called, the behavior is undefined.  Some kind of subtle or
  //     unsubtle chaos is sure to result.
  // https://man7.org/linux/man-pages/man3/longjmp.3.html
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    jmp_buf jump_buf;
    mte_illegal_setjmp_helper(jump_buf);
    longjmp(jump_buf, 1);
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // In our test-case, we have a NEGATIVE stack adjustment, which is being
  // interpreted as unsigned integer, and thus is "too large".
  // TODO(fmayer): fix the error message for this
  ASSERT_MATCH(result, R"(memtag_handle_longjmp: stack adjustment too large)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, mte_async) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelAsync();
    volatile int* p = (volatile int*)malloc(16);
    p[-1] = 42;
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code [89] \(SEGV_MTE[AS]ERR\), fault addr)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, mte_multiple_causes) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  LogcatCollector logcat_collector;

  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    SetTagCheckingLevelSync();

    // Make two allocations with the same tag and close to one another. Check for both properties
    // with a bounds check -- this relies on the fact that only if the allocations have the same tag
    // would they be measured as closer than 128 bytes to each other. Otherwise they would be about
    // (some non-zero value << 56) apart.
    //
    // The out-of-bounds access will be considered either an overflow of one or an underflow of the
    // other.
    std::set<uintptr_t> allocs;
    for (int i = 0; i != 4096; ++i) {
      uintptr_t alloc = reinterpret_cast<uintptr_t>(malloc(16));
      auto it = allocs.insert(alloc).first;
      if (it != allocs.begin() && *std::prev(it) + 128 > alloc) {
        *reinterpret_cast<int*>(*std::prev(it) + 16) = 42;
      }
      if (std::next(it) != allocs.end() && alloc + 128 > *std::next(it)) {
        *reinterpret_cast<int*>(alloc + 16) = 42;
      }
    }
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::vector<std::string> log_sources(2);
  ConsumeFd(std::move(output_fd), &log_sources[0]);
  logcat_collector.Collect(&log_sources[1]);

  // Tag dump only in the tombstone, not logcat.
  ASSERT_MATCH(log_sources[0], "Memory tags around the fault address");

  for (const auto& result : log_sources) {
    ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
    ASSERT_THAT(result, HasSubstr("Note: multiple potential causes for this crash were detected, "
                                  "listing them in decreasing order of likelihood."));
    // Adjacent untracked allocations may cause us to see the wrong underflow here (or only
    // overflows), so we can't match explicitly for an underflow message.
    ASSERT_MATCH(result,
                 R"(Cause: \[MTE\]: Buffer Overflow, 0 bytes right of a 16-byte allocation)");
    // Ensure there's at least two allocation traces (one for each cause).
    ASSERT_MATCH(
        result,
        R"((^|\s)allocated by thread .*?\n.*#00 pc(.|\n)*?(^|\s)allocated by thread .*?\n.*#00 pc)");
  }
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

#if defined(__aarch64__)
static uintptr_t CreateTagMapping() {
  // Some of the MTE tag dump tests assert that there is an inaccessible page to the left and right
  // of the PROT_MTE page, so map three pages and set the two guard pages to PROT_NONE.
  size_t page_size = getpagesize();
  void* mapping = mmap(nullptr, page_size * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  uintptr_t mapping_uptr = reinterpret_cast<uintptr_t>(mapping);
  if (mapping == MAP_FAILED) {
    return 0;
  }
  mprotect(reinterpret_cast<void*>(mapping_uptr + page_size), page_size,
           PROT_READ | PROT_WRITE | PROT_MTE);
  // Stripe the mapping, where even granules get tag '1', and odd granules get tag '0'.
  for (uintptr_t offset = 0; offset < page_size; offset += 2 * kTagGranuleSize) {
    uintptr_t tagged_addr = mapping_uptr + page_size + offset + (1ULL << 56);
    __asm__ __volatile__(".arch_extension mte; stg %0, [%0]" : : "r"(tagged_addr) : "memory");
  }
  return mapping_uptr + page_size;
}
#endif

TEST_F(CrasherTest, mte_register_tag_dump) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    Trap(reinterpret_cast<void *>(CreateTagMapping()));
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(memory near x0:
.*
.*
    01.............0 0000000000000000 0000000000000000  ................
    00.............0)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, mte_fault_tag_dump_front_truncated) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    volatile char* p = reinterpret_cast<char*>(CreateTagMapping());
    p[0] = 0;  // Untagged pointer, tagged memory.
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(Memory tags around the fault address.*
\s*=>0x[0-9a-f]+000:\[1\] 0  1  0)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, mte_fault_tag_dump) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    volatile char* p = reinterpret_cast<char*>(CreateTagMapping());
    p[320] = 0;  // Untagged pointer, tagged memory.
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(Memory tags around the fault address.*
\s*0x[0-9a-f]+: 1  0  1  0  1  0  1  0  1  0  1  0  1  0  1  0
\s*=>0x[0-9a-f]+: 1  0  1  0 \[1\] 0  1  0  1  0  1  0  1  0  1  0
\s*0x[0-9a-f]+: 1  0  1  0  1  0  1  0  1  0  1  0  1  0  1  0
)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, mte_fault_tag_dump_rear_truncated) {
#if defined(__aarch64__)
  if (!mte_supported() || !mte_enabled()) {
    GTEST_SKIP() << "Requires MTE";
  }

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&]() {
    SetTagCheckingLevelSync();
    size_t page_size = getpagesize();
    volatile char* p = reinterpret_cast<char*>(CreateTagMapping());
    p[page_size - kTagGranuleSize * 2] = 0;  // Untagged pointer, tagged memory.
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(Memory tags around the fault address)");
  ASSERT_MATCH(result,
               R"(\s*0x[0-9a-f]+: 1  0  1  0  1  0  1  0  1  0  1  0  1  0  1  0
\s*=>0x[0-9a-f]+: 1  0  1  0  1  0  1  0  1  0  1  0  1  0 \[1\] 0

)");  // Ensure truncation happened and there's a newline after the tag fault.
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, LD_PRELOAD) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    setenv("LD_PRELOAD", "nonexistent.so", 1);
    *reinterpret_cast<volatile char*>(0xdead) = '1';
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0+dead)");
}

TEST_F(CrasherTest, abort) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "abort");
}

TEST_F(CrasherTest, signal) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    while (true) {
      sleep(1);
    }
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  ASSERT_EQ(0, kill(crasher_pid, SIGSEGV));

  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(
      result,
      R"(signal 11 \(SIGSEGV\), code 0 \(SI_USER from pid \d+, uid \d+\), fault addr --------)");
  ASSERT_MATCH(result, R"(backtrace:)");
}

TEST_F(CrasherTest, abort_message) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    // Arrived at experimentally;
    // logd truncates at 4062.
    // strlen("Abort message: ''") is 17.
    // That's 4045, but we also want a NUL.
    char buf[4045 + 1];
    memset(buf, 'x', sizeof(buf));
    buf[sizeof(buf) - 1] = '\0';
    android_set_abort_message(buf);
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(Abort message: 'x{4045}')");
}

static char g_crash_detail_value_changes[] = "crash_detail_value";
static char g_crash_detail_value[] = "crash_detail_value";
static char g_crash_detail_value2[] = "crash_detail_value2";

inline crash_detail_t* _Nullable android_register_crash_detail_strs(const char* _Nonnull name,
                                                                    const char* _Nonnull data) {
  return android_crash_detail_register(name, strlen(name), data, strlen(data));
}

TEST_F(CrasherTest, crash_detail_single) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value);
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME: 'crash_detail_value')");
}

TEST_F(CrasherTest, crash_detail_replace_data) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    auto *cd = android_register_crash_detail_strs("CRASH_DETAIL_NAME", "original_data");
    android_crash_detail_replace_data(cd, "new_data", strlen("new_data"));
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME: 'new_data')");
  // Ensure the old one no longer shows up, i.e. that we actually replaced
  // it, not added a new one.
  ASSERT_NOT_MATCH(result, R"(CRASH_DETAIL_NAME: 'original_data')");
}

TEST_F(CrasherTest, crash_detail_replace_name) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    auto *cd = android_register_crash_detail_strs("old_name", g_crash_detail_value);
    android_crash_detail_replace_name(cd, "new_name", strlen("new_name"));
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(new_name: 'crash_detail_value')");
  // Ensure the old one no longer shows up, i.e. that we actually replaced
  // it, not added a new one.
  ASSERT_NOT_MATCH(result, R"(old_name: 'crash_detail_value')");
}

TEST_F(CrasherTest, crash_detail_single_byte_name) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_register_crash_detail_strs("CRASH_DETAIL_NAME\1", g_crash_detail_value);
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME\\1: 'crash_detail_value')");
}


TEST_F(CrasherTest, crash_detail_single_bytes) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_crash_detail_register("CRASH_DETAIL_NAME", strlen("CRASH_DETAIL_NAME"), "\1",
                                  sizeof("\1"));
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME: '\\1\\0')");
}

TEST_F(CrasherTest, crash_detail_mixed) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    const char data[] = "helloworld\1\255\3";
    android_register_crash_detail_strs("CRASH_DETAIL_NAME", data);
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME: 'helloworld\\1\\255\\3')");
}

TEST_F(CrasherTest, crash_detail_many) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    for (int i = 0; i < 1000; ++i) {
      std::string name = "CRASH_DETAIL_NAME" + std::to_string(i);
      std::string value = "CRASH_DETAIL_VALUE" + std::to_string(i);
      auto* h = android_register_crash_detail_strs(name.data(), value.data());
      android_crash_detail_unregister(h);
    }

    android_register_crash_detail_strs("FINAL_NAME", "FINAL_VALUE");
    android_register_crash_detail_strs("FINAL_NAME2", "FINAL_VALUE2");
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_NOT_MATCH(result, "CRASH_DETAIL_NAME");
  ASSERT_NOT_MATCH(result, "CRASH_DETAIL_VALUE");
  ASSERT_MATCH(result, R"(FINAL_NAME: 'FINAL_VALUE')");
  ASSERT_MATCH(result, R"(FINAL_NAME2: 'FINAL_VALUE2')");
}

TEST_F(CrasherTest, crash_detail_single_changes) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value_changes);
    g_crash_detail_value_changes[0] = 'C';
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME: 'Crash_detail_value')");
}

TEST_F(CrasherTest, crash_detail_multiple) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value);
    android_register_crash_detail_strs("CRASH_DETAIL_NAME2", g_crash_detail_value2);
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME: 'crash_detail_value')");
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME2: 'crash_detail_value2')");
}

TEST_F(CrasherTest, crash_detail_remove) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    auto* detail1 = android_register_crash_detail_strs("CRASH_DETAIL_NAME", g_crash_detail_value);
    android_crash_detail_unregister(detail1);
    android_register_crash_detail_strs("CRASH_DETAIL_NAME2", g_crash_detail_value2);
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_NOT_MATCH(result, R"(CRASH_DETAIL_NAME: 'crash_detail_value')");
  ASSERT_MATCH(result, R"(CRASH_DETAIL_NAME2: 'crash_detail_value2')");
}

TEST_F(CrasherTest, abort_message_newline_trimmed) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_set_abort_message("Message with a newline.\n");
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(Abort message: 'Message with a newline.')");
}

TEST_F(CrasherTest, abort_message_multiple_newlines_trimmed) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_set_abort_message("Message with multiple newlines.\n\n\n\n\n");
    abort();
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(Abort message: 'Message with multiple newlines.')");
}

TEST_F(CrasherTest, abort_message_backtrace) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    android_set_abort_message("not actually aborting");
    raise(BIONIC_SIGNAL_DEBUGGER);
    exit(0);
  });
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_NOT_MATCH(result, R"(Abort message:)");
}

TEST_F(CrasherTest, intercept_timeout) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd);

  // Don't let crasher finish until we timeout.
  FinishIntercept(&intercept_result);

  ASSERT_NE(1, intercept_result) << "tombstoned reported success? (intercept_result = "
                                 << intercept_result << ")";

  FinishCrasher();
  AssertDeath(SIGABRT);
}

TEST_F(CrasherTest, wait_for_debugger) {
  if (!android::base::SetProperty(kWaitForDebuggerKey, "1")) {
    FAIL() << "failed to enable wait_for_debugger";
  }
  sleep(1);

  StartProcess([]() {
    abort();
  });
  FinishCrasher();

  int status;
  ASSERT_EQ(crasher_pid, TEMP_FAILURE_RETRY(waitpid(crasher_pid, &status, WUNTRACED)));
  ASSERT_TRUE(WIFSTOPPED(status));
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status));

  ASSERT_EQ(0, kill(crasher_pid, SIGCONT));

  AssertDeath(SIGABRT);
}

TEST_F(CrasherTest, backtrace) {
  std::string result;
  int intercept_result;
  unique_fd output_fd;

  StartProcess([]() {
    abort();
  });
  StartIntercept(&output_fd, kDebuggerdNativeBacktrace);

  std::this_thread::sleep_for(500ms);

  sigval val;
  val.sival_int = 1;
  ASSERT_EQ(0, sigqueue(crasher_pid, BIONIC_SIGNAL_DEBUGGER, val)) << strerror(errno);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "read");

  int status;
  ASSERT_EQ(0, waitpid(crasher_pid, &status, WNOHANG | WUNTRACED));

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "abort");
}

TEST_F(CrasherTest, PR_SET_DUMPABLE_0_crash) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    prctl(PR_SET_DUMPABLE, 0);
    abort();
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "abort");
}

TEST_F(CrasherTest, capabilities) {
  ASSERT_EQ(0U, getuid()) << "capability test requires root";

  StartProcess([]() {
    if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0) {
      err(1, "failed to set PR_SET_KEEPCAPS");
    }

    if (setresuid(1, 1, 1) != 0) {
      err(1, "setresuid failed");
    }

    __user_cap_header_struct capheader;
    __user_cap_data_struct capdata[2];
    memset(&capheader, 0, sizeof(capheader));
    memset(&capdata, 0, sizeof(capdata));

    capheader.version = _LINUX_CAPABILITY_VERSION_3;
    capheader.pid = 0;

    // Turn on every third capability.
    static_assert(CAP_LAST_CAP > 33, "CAP_LAST_CAP <= 32");
    for (int i = 0; i < CAP_LAST_CAP; i += 3) {
      capdata[CAP_TO_INDEX(i)].permitted |= CAP_TO_MASK(i);
      capdata[CAP_TO_INDEX(i)].effective |= CAP_TO_MASK(i);
    }

    // Make sure CAP_SYS_PTRACE is off.
    capdata[CAP_TO_INDEX(CAP_SYS_PTRACE)].permitted &= ~(CAP_TO_MASK(CAP_SYS_PTRACE));
    capdata[CAP_TO_INDEX(CAP_SYS_PTRACE)].effective &= ~(CAP_TO_MASK(CAP_SYS_PTRACE));

    if (capset(&capheader, &capdata[0]) != 0) {
      err(1, "capset failed");
    }

    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0) {
      err(1, "failed to drop ambient capabilities");
    }

    pthread_setname_np(pthread_self(), "thread_name");
    raise(SIGSYS);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSYS);

  std::string result;
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(name: thread_name\s+>>> .+debuggerd_test(32|64) <<<)");
  ASSERT_BACKTRACE_FRAME(result, "tgkill");
}

TEST_F(CrasherTest, fake_pid) {
  int intercept_result;
  unique_fd output_fd;

  // Prime the getpid/gettid caches.
  UNUSED(getpid());
  UNUSED(gettid());

  std::function<pid_t()> clone_fn = []() {
    return syscall(__NR_clone, SIGCHLD, nullptr, nullptr, nullptr, nullptr);
  };
  StartProcess(
      []() {
        ASSERT_NE(getpid(), syscall(__NR_getpid));
        ASSERT_NE(gettid(), syscall(__NR_gettid));
        raise(SIGSEGV);
      },
      clone_fn);

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "tgkill");
}

static const char* const kDebuggerdSeccompPolicy =
    "/system/etc/seccomp_policy/crash_dump." ABI_STRING ".policy";

static void setup_jail(minijail* jail) {
  if (!jail) {
    LOG(FATAL) << "failed to create minijail";
  }

  std::string policy;
  if (!android::base::ReadFileToString(kDebuggerdSeccompPolicy, &policy)) {
    PLOG(FATAL) << "failed to read policy file";
  }

  // Allow a bunch of syscalls used by the tests.
  policy += "\nclone: 1";
  policy += "\nsigaltstack: 1";
  policy += "\nnanosleep: 1";
  policy += "\ngetrlimit: 1";
  policy += "\nugetrlimit: 1";

  FILE* tmp_file = tmpfile();
  if (!tmp_file) {
    PLOG(FATAL) << "tmpfile failed";
  }

  unique_fd tmp_fd(TEMP_FAILURE_RETRY(dup(fileno(tmp_file))));
  if (!android::base::WriteStringToFd(policy, tmp_fd.get())) {
    PLOG(FATAL) << "failed to write policy to tmpfile";
  }

  if (lseek(tmp_fd.get(), 0, SEEK_SET) != 0) {
    PLOG(FATAL) << "failed to seek tmp_fd";
  }

  minijail_no_new_privs(jail);
  minijail_log_seccomp_filter_failures(jail);
  minijail_use_seccomp_filter(jail);
  minijail_parse_seccomp_filters_from_fd(jail, tmp_fd.release());
}

static pid_t seccomp_fork_impl(void (*prejail)()) {
  ScopedMinijail jail{minijail_new()};
  setup_jail(jail.get());

  pid_t result = fork();
  if (result == -1) {
    return result;
  } else if (result != 0) {
    return result;
  }

  // Spawn and detach a thread that spins forever.
  std::atomic<bool> thread_ready(false);
  std::thread thread([&jail, &thread_ready]() {
    minijail_enter(jail.get());
    thread_ready = true;
    for (;;)
      ;
  });
  thread.detach();

  while (!thread_ready) {
    continue;
  }

  if (prejail) {
    prejail();
  }

  minijail_enter(jail.get());
  return result;
}

static pid_t seccomp_fork() {
  return seccomp_fork_impl(nullptr);
}

TEST_F(CrasherTest, seccomp_crash) {
  int intercept_result;
  unique_fd output_fd;

  StartProcess([]() { abort(); }, &seccomp_fork);

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "abort");
}

static pid_t seccomp_fork_rlimit() {
  return seccomp_fork_impl([]() {
    struct rlimit rlim = {
        .rlim_cur = 512 * 1024 * 1024,
        .rlim_max = 512 * 1024 * 1024,
    };

    if (setrlimit(RLIMIT_AS, &rlim) != 0) {
      raise(SIGINT);
    }
  });
}

TEST_F(CrasherTest, seccomp_crash_oom) {
  int intercept_result;
  unique_fd output_fd;

  StartProcess(
      []() {
        std::vector<void*> vec;
        for (int i = 0; i < 512; ++i) {
          char* buf = static_cast<char*>(malloc(1024 * 1024));
          if (!buf) {
            abort();
          }
          memset(buf, 0xff, 1024 * 1024);
          vec.push_back(buf);
        }
      },
      &seccomp_fork_rlimit);

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  // We can't actually generate a backtrace, just make sure that the process terminates.
}

__attribute__((__noinline__)) extern "C" bool raise_debugger_signal(DebuggerdDumpType dump_type) {
  siginfo_t siginfo;
  siginfo.si_code = SI_QUEUE;
  siginfo.si_pid = getpid();
  siginfo.si_uid = getuid();

  if (dump_type != kDebuggerdNativeBacktrace && dump_type != kDebuggerdTombstone) {
    PLOG(FATAL) << "invalid dump type";
  }

  siginfo.si_value.sival_int = dump_type == kDebuggerdNativeBacktrace;

  if (syscall(__NR_rt_tgsigqueueinfo, getpid(), gettid(), BIONIC_SIGNAL_DEBUGGER, &siginfo) != 0) {
    PLOG(ERROR) << "libdebuggerd_client: failed to send signal to self";
    return false;
  }

  return true;
}

extern "C" void foo() {
  LOG(INFO) << "foo";
  std::this_thread::sleep_for(1s);
}

extern "C" void bar() {
  LOG(INFO) << "bar";
  std::this_thread::sleep_for(1s);
}

TEST_F(CrasherTest, seccomp_tombstone) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdTombstone;
  StartProcess(
      []() {
        std::thread a(foo);
        std::thread b(bar);

        std::this_thread::sleep_for(100ms);

        raise_debugger_signal(dump_type);
        _exit(0);
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
  ASSERT_BACKTRACE_FRAME(result, "foo");
  ASSERT_BACKTRACE_FRAME(result, "bar");
}

TEST_F(CrasherTest, seccomp_tombstone_thread_abort) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdTombstone;
  StartProcess(
      []() {
        std::thread abort_thread([] { abort(); });
        abort_thread.join();
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(
      result,
      R"(signal 6 \(SIGABRT\))");
  ASSERT_BACKTRACE_FRAME(result, "abort");
}

TEST_F(CrasherTest, seccomp_tombstone_multiple_threads_abort) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdTombstone;
  StartProcess(
      []() {
        std::thread a(foo);
        std::thread b(bar);

        std::this_thread::sleep_for(100ms);

        std::thread abort_thread([] { abort(); });
        abort_thread.join();
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "abort");
  ASSERT_BACKTRACE_FRAME(result, "foo");
  ASSERT_BACKTRACE_FRAME(result, "bar");
  ASSERT_BACKTRACE_FRAME(result, "main");
}

TEST_F(CrasherTest, seccomp_backtrace) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdNativeBacktrace;
  StartProcess(
      []() {
        std::thread a(foo);
        std::thread b(bar);

        std::this_thread::sleep_for(100ms);

        raise_debugger_signal(dump_type);
        _exit(0);
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
  ASSERT_BACKTRACE_FRAME(result, "foo");
  ASSERT_BACKTRACE_FRAME(result, "bar");
}

TEST_F(CrasherTest, seccomp_backtrace_from_thread) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdNativeBacktrace;
  StartProcess(
      []() {
        std::thread a(foo);
        std::thread b(bar);

        std::this_thread::sleep_for(100ms);

        std::thread raise_thread([] {
          raise_debugger_signal(dump_type);
          _exit(0);
        });
        raise_thread.join();
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
  ASSERT_BACKTRACE_FRAME(result, "foo");
  ASSERT_BACKTRACE_FRAME(result, "bar");
  ASSERT_BACKTRACE_FRAME(result, "main");
}

TEST_F(CrasherTest, seccomp_crash_logcat) {
  StartProcess([]() { abort(); }, &seccomp_fork);
  FinishCrasher();

  // Make sure we don't get SIGSYS when trying to dump a crash to logcat.
  AssertDeath(SIGABRT);
}

extern "C" void malloc_enable();
extern "C" void malloc_disable();

TEST_F(CrasherTest, seccomp_tombstone_no_allocation) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdTombstone;
  StartProcess(
      []() {
        std::thread a(foo);
        std::thread b(bar);

        std::this_thread::sleep_for(100ms);

        // Disable allocations to verify that nothing in the fallback
        // signal handler does an allocation.
        malloc_disable();
        raise_debugger_signal(dump_type);
        _exit(0);
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
  ASSERT_BACKTRACE_FRAME(result, "foo");
  ASSERT_BACKTRACE_FRAME(result, "bar");
}

TEST_F(CrasherTest, seccomp_backtrace_no_allocation) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdNativeBacktrace;
  StartProcess(
      []() {
        std::thread a(foo);
        std::thread b(bar);

        std::this_thread::sleep_for(100ms);

        // Disable allocations to verify that nothing in the fallback
        // signal handler does an allocation.
        malloc_disable();
        raise_debugger_signal(dump_type);
        _exit(0);
      },
      &seccomp_fork);

  StartIntercept(&output_fd, dump_type);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
  ASSERT_BACKTRACE_FRAME(result, "foo");
  ASSERT_BACKTRACE_FRAME(result, "bar");
}

TEST_F(CrasherTest, competing_tracer) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    raise(SIGABRT);
  });

  StartIntercept(&output_fd);

  ASSERT_EQ(0, ptrace(PTRACE_SEIZE, crasher_pid, 0, 0));
  FinishCrasher();

  int status;
  ASSERT_EQ(crasher_pid, TEMP_FAILURE_RETRY(waitpid(crasher_pid, &status, 0)));
  ASSERT_TRUE(WIFSTOPPED(status));
  ASSERT_EQ(SIGABRT, WSTOPSIG(status));

  ASSERT_EQ(0, ptrace(PTRACE_CONT, crasher_pid, 0, SIGABRT));
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  std::string regex = R"(failed to attach to thread \d+, already traced by )";
  regex += std::to_string(gettid());
  regex += R"( \(.+debuggerd_test)";
  ASSERT_MATCH(result, regex.c_str());

  ASSERT_EQ(crasher_pid, TEMP_FAILURE_RETRY(waitpid(crasher_pid, &status, 0)));
  ASSERT_TRUE(WIFSTOPPED(status));
  ASSERT_EQ(SIGABRT, WSTOPSIG(status));

  ASSERT_EQ(0, ptrace(PTRACE_DETACH, crasher_pid, 0, SIGABRT));
  AssertDeath(SIGABRT);
}

struct GwpAsanTestParameters {
  size_t alloc_size;
  bool free_before_access;
  int access_offset;
  std::string cause_needle;  // Needle to be found in the "Cause: [GWP-ASan]" line.
};

struct GwpAsanCrasherTest
    : CrasherTest,
      testing::WithParamInterface<
          std::tuple<GwpAsanTestParameters, /* recoverable */ bool, /* seccomp */ bool>> {};

GwpAsanTestParameters gwp_asan_tests[] = {
    {/* alloc_size */ 7, /* free_before_access */ true, /* access_offset */ 0,
     "Use After Free, 0 bytes into a 7-byte allocation"},
    {/* alloc_size */ 15, /* free_before_access */ true, /* access_offset */ 1,
     "Use After Free, 1 byte into a 15-byte allocation"},
    {/* alloc_size */ static_cast<size_t>(getpagesize()), /* free_before_access */ false,
     /* access_offset */ getpagesize() + 2,
     android::base::StringPrintf("Buffer Overflow, 2 bytes right of a %d-byte allocation",
                                 getpagesize())},
    {/* alloc_size */ static_cast<size_t>(getpagesize()), /* free_before_access */ false,
     /* access_offset */ -1,
     android::base::StringPrintf("Buffer Underflow, 1 byte left of a %d-byte allocation",
                                 getpagesize())},
};

INSTANTIATE_TEST_SUITE_P(
    GwpAsanTests, GwpAsanCrasherTest,
    testing::Combine(testing::ValuesIn(gwp_asan_tests),
                     /* recoverable */ testing::Bool(),
                     /* seccomp */ testing::Bool()),
    [](const testing::TestParamInfo<
        std::tuple<GwpAsanTestParameters, /* recoverable */ bool, /* seccomp */ bool>>& info) {
      const GwpAsanTestParameters& params = std::get<0>(info.param);
      std::string name = params.free_before_access ? "UseAfterFree" : "Overflow";
      name += testing::PrintToString(params.alloc_size);
      name += "Alloc";
      if (params.access_offset < 0) {
        name += "Left";
        name += testing::PrintToString(params.access_offset * -1);
      } else {
        name += "Right";
        name += testing::PrintToString(params.access_offset);
      }
      name += "Bytes";
      if (std::get<1>(info.param)) name += "Recoverable";
      if (std::get<2>(info.param)) name += "Seccomp";
      return name;
    });

TEST_P(GwpAsanCrasherTest, run_gwp_asan_test) {
  if (mte_supported()) {
    // Skip this test on MTE hardware, as MTE will reliably catch these errors
    // instead of GWP-ASan.
    GTEST_SKIP() << "Skipped on MTE.";
  }
  // Skip this test on HWASan, which will reliably catch test errors as well.
  SKIP_WITH_HWASAN;

  GwpAsanTestParameters params = std::get<0>(GetParam());
  bool recoverable = std::get<1>(GetParam());
  LogcatCollector logcat_collector;

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&recoverable]() {
    const char* env[] = {"GWP_ASAN_SAMPLE_RATE=1", "GWP_ASAN_PROCESS_SAMPLING=1",
                         "GWP_ASAN_MAX_ALLOCS=40000", nullptr, nullptr};
    if (!recoverable) {
      env[3] = "GWP_ASAN_RECOVERABLE=false";
    }
    std::string test_name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
    test_name = std::regex_replace(test_name, std::regex("run_gwp_asan_test"),
                                   "DISABLED_run_gwp_asan_test");
    std::string test_filter = "--gtest_filter=*";
    test_filter += test_name;
    std::string this_binary = android::base::GetExecutablePath();
    const char* args[] = {this_binary.c_str(), "--gtest_also_run_disabled_tests",
                          test_filter.c_str(), nullptr};
    // We check the crash report from a debuggerd handler and from logcat. The
    // echo from stdout/stderr of the subprocess trips up atest, because it
    // doesn't like that two tests started in a row without the first one
    // finishing (even though the second one is in a subprocess).
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    execve(this_binary.c_str(), const_cast<char**>(args), const_cast<char**>(env));
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  if (recoverable) {
    AssertDeath(0);
  } else {
    AssertDeath(SIGSEGV);
  }
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::vector<std::string> log_sources(2);
  ConsumeFd(std::move(output_fd), &log_sources[0]);
  logcat_collector.Collect(&log_sources[1]);

  // seccomp forces the fallback handler, which doesn't print GWP-ASan debugging
  // information. Make sure the recovery still works, but the report won't be
  // hugely useful, it looks like a regular SEGV.
  bool seccomp = std::get<2>(GetParam());
  if (!seccomp) {
    for (const auto& result : log_sources) {
      ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 2 \(SEGV_ACCERR\))");
      ASSERT_MATCH(result, R"(Cause: \[GWP-ASan\]: )" + params.cause_needle);
      if (params.free_before_access) {
        ASSERT_MATCH(result, R"(deallocated by thread .*\n.*#00 pc)");
      }
      ASSERT_MATCH(result, R"((^|\s)allocated by thread .*\n.*#00 pc)");
    }
  }
}

TEST_P(GwpAsanCrasherTest, DISABLED_run_gwp_asan_test) {
  GwpAsanTestParameters params = std::get<0>(GetParam());
  bool seccomp = std::get<2>(GetParam());
  if (seccomp) {
    ScopedMinijail jail{minijail_new()};
    setup_jail(jail.get());
    minijail_enter(jail.get());
  }

  // Use 'volatile' to prevent a very clever compiler eliminating the store.
  char* volatile p = reinterpret_cast<char* volatile>(malloc(params.alloc_size));
  if (params.free_before_access) free(static_cast<void*>(const_cast<char*>(p)));
  p[params.access_offset] = 42;
  if (!params.free_before_access) free(static_cast<void*>(const_cast<char*>(p)));

  bool recoverable = std::get<1>(GetParam());
  ASSERT_TRUE(recoverable);  // Non-recoverable should have crashed.

  // As we're in recoverable mode, trigger another 2x use-after-frees (ensuring
  // we end with at least one in a different slot), make sure the process still
  // doesn't crash.
  p = reinterpret_cast<char* volatile>(malloc(params.alloc_size));
  char* volatile p2 = reinterpret_cast<char* volatile>(malloc(params.alloc_size));
  free(static_cast<void*>(const_cast<char*>(p)));
  free(static_cast<void*>(const_cast<char*>(p2)));
  *p = 42;
  *p2 = 42;

  // Under clang coverage (which is a default TEST_MAPPING presubmit target), the
  // recoverable+seccomp tests fail because the minijail prevents some atexit syscalls that clang
  // coverage does. Thus, skip the atexit handlers.
  _exit(0);
}

TEST_F(CrasherTest, fdsan_warning_abort_message) {
  int intercept_result;
  unique_fd output_fd;

  StartProcess([]() {
    android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
    unique_fd fd(TEMP_FAILURE_RETRY(open("/dev/null", O_RDONLY | O_CLOEXEC)));
    if (fd == -1) {
      abort();
    }
    close(fd.get());
    _exit(0);
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(0);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, "Abort message: 'attempted to close");
}

TEST(crash_dump, zombie) {
  pid_t forkpid = fork();

  pid_t rc;
  int status;

  if (forkpid == 0) {
    errno = 0;
    rc = waitpid(-1, &status, WNOHANG | __WALL | __WNOTHREAD);
    if (rc != -1 || errno != ECHILD) {
      errx(2, "first waitpid returned %d (%s), expected failure with ECHILD", rc, strerror(errno));
    }

    raise(BIONIC_SIGNAL_DEBUGGER);

    errno = 0;
    rc = TEMP_FAILURE_RETRY(waitpid(-1, &status, __WALL | __WNOTHREAD));
    if (rc != -1 || errno != ECHILD) {
      errx(2, "second waitpid returned %d (%s), expected failure with ECHILD", rc, strerror(errno));
    }
    _exit(0);
  } else {
    rc = TEMP_FAILURE_RETRY(waitpid(forkpid, &status, 0));
    ASSERT_EQ(forkpid, rc);
    ASSERT_TRUE(WIFEXITED(status));
    ASSERT_EQ(0, WEXITSTATUS(status));
  }
}

TEST(tombstoned, no_notify) {
  // Do this a few times.
  for (int i = 0; i < 3; ++i) {
    pid_t pid = 123'456'789 + i;

    unique_fd intercept_fd, output_fd;
    InterceptResponse response = {};
    tombstoned_intercept(pid, &intercept_fd, &output_fd, &response, kDebuggerdTombstone);
    ASSERT_EQ(InterceptStatus::kRegistered, response.status)
        << "Error message: " << response.error_message;

    {
      unique_fd tombstoned_socket, input_fd;
      ASSERT_TRUE(tombstoned_connect(pid, &tombstoned_socket, &input_fd, kDebuggerdTombstone));
      ASSERT_TRUE(android::base::WriteFully(input_fd.get(), &pid, sizeof(pid)));
    }

    pid_t read_pid;
    ASSERT_TRUE(android::base::ReadFully(output_fd.get(), &read_pid, sizeof(read_pid)));
    ASSERT_EQ(read_pid, pid);
  }
}

TEST(tombstoned, stress) {
  // Spawn threads to simultaneously do a bunch of failing dumps and a bunch of successful dumps.
  static constexpr int kDumpCount = 100;

  std::atomic<bool> start(false);
  std::vector<std::thread> threads;
  threads.emplace_back([&start]() {
    while (!start) {
      continue;
    }

    // Use a way out of range pid, to avoid stomping on an actual process.
    pid_t pid_base = 1'000'000;

    for (int dump = 0; dump < kDumpCount; ++dump) {
      pid_t pid = pid_base + dump;

      unique_fd intercept_fd, output_fd;
      InterceptResponse response = {};
      tombstoned_intercept(pid, &intercept_fd, &output_fd, &response, kDebuggerdTombstone);
      ASSERT_EQ(InterceptStatus::kRegistered, response.status)
          << "Error messeage: " << response.error_message;

      // Pretend to crash, and then immediately close the socket.
      unique_fd sockfd(socket_local_client(kTombstonedCrashSocketName,
                                           ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
      if (sockfd == -1) {
        FAIL() << "failed to connect to tombstoned: " << strerror(errno);
      }
      TombstonedCrashPacket packet = {};
      packet.packet_type = CrashPacketType::kDumpRequest;
      packet.packet.dump_request.pid = pid;
      if (TEMP_FAILURE_RETRY(write(sockfd, &packet, sizeof(packet))) != sizeof(packet)) {
        FAIL() << "failed to write to tombstoned: " << strerror(errno);
      }

      continue;
    }
  });

  threads.emplace_back([&start]() {
    while (!start) {
      continue;
    }

    // Use a way out of range pid, to avoid stomping on an actual process.
    pid_t pid_base = 2'000'000;

    for (int dump = 0; dump < kDumpCount; ++dump) {
      pid_t pid = pid_base + dump;

      unique_fd intercept_fd, output_fd;
      InterceptResponse response = {};
      tombstoned_intercept(pid, &intercept_fd, &output_fd, &response, kDebuggerdTombstone);
      ASSERT_EQ(InterceptStatus::kRegistered, response.status)
          << "Error message: " << response.error_message;

      {
        unique_fd tombstoned_socket, input_fd;
        ASSERT_TRUE(tombstoned_connect(pid, &tombstoned_socket, &input_fd, kDebuggerdTombstone));
        ASSERT_TRUE(android::base::WriteFully(input_fd.get(), &pid, sizeof(pid)));
        tombstoned_notify_completion(tombstoned_socket.get());
      }

      // TODO: Fix the race that requires this sleep.
      std::this_thread::sleep_for(50ms);

      pid_t read_pid;
      ASSERT_TRUE(android::base::ReadFully(output_fd.get(), &read_pid, sizeof(read_pid)));
      ASSERT_EQ(read_pid, pid);
    }
  });

  start = true;

  for (std::thread& thread : threads) {
    thread.join();
  }
}

TEST(tombstoned, intercept_java_trace_smoke) {
  // Using a "real" PID is a little dangerous here - if the test fails
  // or crashes, we might end up getting a bogus / unreliable stack
  // trace.
  const pid_t self = getpid();

  unique_fd intercept_fd, output_fd;
  InterceptResponse response = {};
  tombstoned_intercept(self, &intercept_fd, &output_fd, &response, kDebuggerdJavaBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  // First connect to tombstoned requesting a native tombstone. This
  // should result in a "regular" FD and not the installed intercept.
  const char native[] = "native";
  unique_fd tombstoned_socket, input_fd;
  ASSERT_TRUE(tombstoned_connect(self, &tombstoned_socket, &input_fd, kDebuggerdTombstone));
  ASSERT_TRUE(android::base::WriteFully(input_fd.get(), native, sizeof(native)));
  tombstoned_notify_completion(tombstoned_socket.get());

  // Then, connect to tombstoned asking for a java backtrace. This *should*
  // trigger the intercept.
  const char java[] = "java";
  ASSERT_TRUE(tombstoned_connect(self, &tombstoned_socket, &input_fd, kDebuggerdJavaBacktrace));
  ASSERT_TRUE(android::base::WriteFully(input_fd.get(), java, sizeof(java)));
  tombstoned_notify_completion(tombstoned_socket.get());

  char outbuf[sizeof(java)];
  ASSERT_TRUE(android::base::ReadFully(output_fd.get(), outbuf, sizeof(outbuf)));
  ASSERT_STREQ("java", outbuf);
}

TEST(tombstoned, intercept_multiple_dump_types) {
  const pid_t fake_pid = 1'234'567;
  unique_fd intercept_fd, output_fd;
  InterceptResponse response = {};
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response, kDebuggerdJavaBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd intercept_fd_2, output_fd_2;
  tombstoned_intercept(fake_pid, &intercept_fd_2, &output_fd_2, &response,
                       kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;
}

TEST(tombstoned, intercept_bad_pid) {
  const pid_t fake_pid = -1;
  unique_fd intercept_fd, output_fd;
  InterceptResponse response = {};
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response, kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kFailed, response.status)
      << "Error message: " << response.error_message;
  ASSERT_MATCH(response.error_message, "bad pid");
}

TEST(tombstoned, intercept_bad_dump_types) {
  const pid_t fake_pid = 1'234'567;
  unique_fd intercept_fd, output_fd;
  InterceptResponse response = {};
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response,
                       static_cast<DebuggerdDumpType>(20));
  ASSERT_EQ(InterceptStatus::kFailed, response.status)
      << "Error message: " << response.error_message;
  ASSERT_MATCH(response.error_message, "bad dump type \\[unknown\\]");

  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response, kDebuggerdAnyIntercept);
  ASSERT_EQ(InterceptStatus::kFailed, response.status)
      << "Error message: " << response.error_message;
  ASSERT_MATCH(response.error_message, "bad dump type kDebuggerdAnyIntercept");

  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response, kDebuggerdTombstoneProto);
  ASSERT_EQ(InterceptStatus::kFailed, response.status)
      << "Error message: " << response.error_message;
  ASSERT_MATCH(response.error_message, "bad dump type kDebuggerdTombstoneProto");
}

TEST(tombstoned, intercept_already_registered) {
  const pid_t fake_pid = 1'234'567;
  unique_fd intercept_fd1, output_fd1;
  InterceptResponse response = {};
  tombstoned_intercept(fake_pid, &intercept_fd1, &output_fd1, &response, kDebuggerdTombstone);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd intercept_fd2, output_fd2;
  tombstoned_intercept(fake_pid, &intercept_fd2, &output_fd2, &response, kDebuggerdTombstone);
  ASSERT_EQ(InterceptStatus::kFailedAlreadyRegistered, response.status)
      << "Error message: " << response.error_message;
  ASSERT_MATCH(response.error_message, "already registered, type kDebuggerdTombstone");
}

TEST(tombstoned, intercept_tombstone_proto_matched_to_tombstone) {
  const pid_t fake_pid = 1'234'567;

  unique_fd intercept_fd, output_fd;
  InterceptResponse response = {};
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response, kDebuggerdTombstone);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  const char data[] = "tombstone_proto";
  unique_fd tombstoned_socket, input_fd;
  ASSERT_TRUE(
      tombstoned_connect(fake_pid, &tombstoned_socket, &input_fd, kDebuggerdTombstoneProto));
  ASSERT_TRUE(android::base::WriteFully(input_fd.get(), data, sizeof(data)));
  tombstoned_notify_completion(tombstoned_socket.get());

  char outbuf[sizeof(data)];
  ASSERT_TRUE(android::base::ReadFully(output_fd.get(), outbuf, sizeof(outbuf)));
  ASSERT_STREQ("tombstone_proto", outbuf);
}

TEST(tombstoned, intercept_any) {
  const pid_t fake_pid = 1'234'567;

  unique_fd intercept_fd, output_fd;
  InterceptResponse response = {};
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &response, kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  const char any[] = "any";
  unique_fd tombstoned_socket, input_fd;
  ASSERT_TRUE(tombstoned_connect(fake_pid, &tombstoned_socket, &input_fd, kDebuggerdAnyIntercept));
  ASSERT_TRUE(android::base::WriteFully(input_fd.get(), any, sizeof(any)));
  tombstoned_notify_completion(tombstoned_socket.get());

  char outbuf[sizeof(any)];
  ASSERT_TRUE(android::base::ReadFully(output_fd.get(), outbuf, sizeof(outbuf)));
  ASSERT_STREQ("any", outbuf);
}

TEST(tombstoned, intercept_any_failed_with_multiple_intercepts) {
  const pid_t fake_pid = 1'234'567;

  InterceptResponse response = {};
  unique_fd intercept_fd1, output_fd1;
  tombstoned_intercept(fake_pid, &intercept_fd1, &output_fd1, &response, kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd intercept_fd2, output_fd2;
  tombstoned_intercept(fake_pid, &intercept_fd2, &output_fd2, &response, kDebuggerdJavaBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd tombstoned_socket, input_fd;
  ASSERT_FALSE(tombstoned_connect(fake_pid, &tombstoned_socket, &input_fd, kDebuggerdAnyIntercept));
}

TEST(tombstoned, intercept_multiple_verify_intercept) {
  // Need to use our pid for java since that will verify the pid.
  const pid_t fake_pid = getpid();

  InterceptResponse response = {};
  unique_fd intercept_fd1, output_fd1;
  tombstoned_intercept(fake_pid, &intercept_fd1, &output_fd1, &response, kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd intercept_fd2, output_fd2;
  tombstoned_intercept(fake_pid, &intercept_fd2, &output_fd2, &response, kDebuggerdJavaBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd intercept_fd3, output_fd3;
  tombstoned_intercept(fake_pid, &intercept_fd3, &output_fd3, &response, kDebuggerdTombstone);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  const char native_data[] = "native";
  unique_fd tombstoned_socket1, input_fd1;
  ASSERT_TRUE(
      tombstoned_connect(fake_pid, &tombstoned_socket1, &input_fd1, kDebuggerdNativeBacktrace));
  ASSERT_TRUE(android::base::WriteFully(input_fd1.get(), native_data, sizeof(native_data)));
  tombstoned_notify_completion(tombstoned_socket1.get());

  char native_outbuf[sizeof(native_data)];
  ASSERT_TRUE(android::base::ReadFully(output_fd1.get(), native_outbuf, sizeof(native_outbuf)));
  ASSERT_STREQ("native", native_outbuf);

  const char java_data[] = "java";
  unique_fd tombstoned_socket2, input_fd2;
  ASSERT_TRUE(
      tombstoned_connect(fake_pid, &tombstoned_socket2, &input_fd2, kDebuggerdJavaBacktrace));
  ASSERT_TRUE(android::base::WriteFully(input_fd2.get(), java_data, sizeof(java_data)));
  tombstoned_notify_completion(tombstoned_socket2.get());

  char java_outbuf[sizeof(java_data)];
  ASSERT_TRUE(android::base::ReadFully(output_fd2.get(), java_outbuf, sizeof(java_outbuf)));
  ASSERT_STREQ("java", java_outbuf);

  const char tomb_data[] = "tombstone";
  unique_fd tombstoned_socket3, input_fd3;
  ASSERT_TRUE(tombstoned_connect(fake_pid, &tombstoned_socket3, &input_fd3, kDebuggerdTombstone));
  ASSERT_TRUE(android::base::WriteFully(input_fd3.get(), tomb_data, sizeof(tomb_data)));
  tombstoned_notify_completion(tombstoned_socket3.get());

  char tomb_outbuf[sizeof(tomb_data)];
  ASSERT_TRUE(android::base::ReadFully(output_fd3.get(), tomb_outbuf, sizeof(tomb_outbuf)));
  ASSERT_STREQ("tombstone", tomb_outbuf);
}

TEST(tombstoned, interceptless_backtrace) {
  // Generate 50 backtraces, and then check to see that we haven't created 50 new tombstones.
  auto get_tombstone_timestamps = []() -> std::map<int, time_t> {
    std::map<int, time_t> result;
    for (int i = 0; i < 99; ++i) {
      std::string path = android::base::StringPrintf("/data/tombstones/tombstone_%02d", i);
      struct stat st;
      if (stat(path.c_str(), &st) == 0) {
        result[i] = st.st_mtim.tv_sec;
      }
    }
    return result;
  };

  auto before = get_tombstone_timestamps();
  for (int i = 0; i < 50; ++i) {
    raise_debugger_signal(kDebuggerdNativeBacktrace);
  }
  auto after = get_tombstone_timestamps();

  int diff = 0;
  for (int i = 0; i < 99; ++i) {
    if (after.count(i) == 0) {
      continue;
    }
    if (before.count(i) == 0) {
      ++diff;
      continue;
    }
    if (before[i] != after[i]) {
      ++diff;
    }
  }

  // We can't be sure that nothing's crash looping in the background.
  // This should be good enough, though...
  ASSERT_LT(diff, 10) << "too many new tombstones; is something crashing in the background?";
}

static __attribute__((__noinline__)) void overflow_stack(void* p) {
  void* buf[1];
  buf[0] = p;
  static volatile void* global = buf;
  if (global) {
    global = buf;
    overflow_stack(&buf);
  }
}

TEST_F(CrasherTest, stack_overflow) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() { overflow_stack(nullptr); });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(Cause: stack pointer[^\n]*stack overflow.\n)");
}

static std::string GetTestLibraryPath() {
  std::string test_lib(testing::internal::GetArgvs()[0]);
  auto const value = test_lib.find_last_of('/');
  if (value == std::string::npos) {
    test_lib = "./";
  } else {
    test_lib = test_lib.substr(0, value + 1) + "./";
  }
  return test_lib + "libcrash_test.so";
}

static void CreateEmbeddedLibrary(int out_fd) {
  std::string test_lib(GetTestLibraryPath());
  android::base::unique_fd fd(open(test_lib.c_str(), O_RDONLY | O_CLOEXEC));
  ASSERT_NE(fd.get(), -1);
  off_t file_size = lseek(fd, 0, SEEK_END);
  ASSERT_EQ(lseek(fd, 0, SEEK_SET), 0);
  std::vector<uint8_t> contents(file_size);
  ASSERT_TRUE(android::base::ReadFully(fd, contents.data(), contents.size()));

  // Put the shared library data at a pagesize() offset.
  ASSERT_EQ(lseek(out_fd, 4 * getpagesize(), SEEK_CUR), 4 * getpagesize());
  ASSERT_EQ(static_cast<size_t>(write(out_fd, contents.data(), contents.size())), contents.size());
}

TEST_F(CrasherTest, non_zero_offset_in_library) {
  int intercept_result;
  unique_fd output_fd;
  TemporaryFile tf;
  CreateEmbeddedLibrary(tf.fd);
  StartProcess([&tf]() {
    android_dlextinfo extinfo{};
    extinfo.flags = ANDROID_DLEXT_USE_LIBRARY_FD | ANDROID_DLEXT_USE_LIBRARY_FD_OFFSET;
    extinfo.library_fd = tf.fd;
    extinfo.library_fd_offset = 4 * getpagesize();
    void* handle = android_dlopen_ext(tf.path, RTLD_NOW, &extinfo);
    if (handle == nullptr) {
      _exit(1);
    }
    void (*crash_func)() = reinterpret_cast<void (*)()>(dlsym(handle, "crash"));
    if (crash_func == nullptr) {
      _exit(1);
    }
    crash_func();
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // Verify the crash includes an offset value in the backtrace.
  std::string match_str = android::base::StringPrintf("%s\\!libcrash_test.so \\(offset 0x%x\\)",
                                                      tf.path, 4 * getpagesize());
  ASSERT_MATCH(result, match_str);
}

static bool CopySharedLibrary(const char* tmp_dir, std::string* tmp_so_name) {
  std::string test_lib(GetTestLibraryPath());

  *tmp_so_name = std::string(tmp_dir) + "/libcrash_test.so";
  std::string cp_cmd = android::base::StringPrintf("cp %s %s", test_lib.c_str(), tmp_dir);

  // Copy the shared so to a tempory directory.
  return system(cp_cmd.c_str()) == 0;
}

TEST_F(CrasherTest, unreadable_elf) {
  int intercept_result;
  unique_fd output_fd;
  std::string tmp_so_name;
  StartProcess([&tmp_so_name]() {
    TemporaryDir td;
    if (!CopySharedLibrary(td.path, &tmp_so_name)) {
      _exit(1);
    }
    void* handle = dlopen(tmp_so_name.c_str(), RTLD_NOW);
    if (handle == nullptr) {
      _exit(1);
    }
    // Delete the original shared library so that we get the warning
    // about unreadable elf files.
    if (unlink(tmp_so_name.c_str()) == -1) {
      _exit(1);
    }
    void (*crash_func)() = reinterpret_cast<void (*)()>(dlsym(handle, "crash"));
    if (crash_func == nullptr) {
      _exit(1);
    }
    crash_func();
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(NOTE: Function names and BuildId information is missing )");
  std::string match_str = "NOTE:   " + tmp_so_name;
  ASSERT_MATCH(result, match_str);
}

void CheckForTombstone(const struct stat& text_st, std::optional<std::string>& tombstone_file) {
  static std::regex tombstone_re("tombstone_\\d+");
  std::unique_ptr<DIR, decltype(&closedir)> dir_h(opendir("/data/tombstones"), closedir);
  ASSERT_TRUE(dir_h != nullptr);
  dirent* entry;
  while ((entry = readdir(dir_h.get())) != nullptr) {
    if (!std::regex_match(entry->d_name, tombstone_re)) {
      continue;
    }
    std::string path = android::base::StringPrintf("/data/tombstones/%s", entry->d_name);

    struct stat st;
    if (TEMP_FAILURE_RETRY(stat(path.c_str(), &st)) != 0) {
      continue;
    }

    if (st.st_dev == text_st.st_dev && st.st_ino == text_st.st_ino) {
      tombstone_file = path;
      break;
    }
  }
}

TEST(tombstoned, proto) {
  const pid_t self = getpid();
  unique_fd tombstoned_socket, text_fd, proto_fd;
  ASSERT_TRUE(
      tombstoned_connect(self, &tombstoned_socket, &text_fd, &proto_fd, kDebuggerdTombstoneProto));

  tombstoned_notify_completion(tombstoned_socket.get());

  ASSERT_NE(-1, text_fd.get());
  ASSERT_NE(-1, proto_fd.get());

  struct stat text_st;
  ASSERT_EQ(0, fstat(text_fd.get(), &text_st));

  std::optional<std::string> tombstone_file;
  // Allow up to 5 seconds for the tombstone to be written to the system.
  const auto max_wait_time = std::chrono::seconds(5) * android::base::HwTimeoutMultiplier();
  const auto start = std::chrono::high_resolution_clock::now();
  while (true) {
    std::this_thread::sleep_for(100ms);
    CheckForTombstone(text_st, tombstone_file);
    if (tombstone_file) {
      break;
    }
    if (std::chrono::high_resolution_clock::now() - start > max_wait_time) {
      break;
    }
  }

  ASSERT_TRUE(tombstone_file) << "Timed out trying to find tombstone file.";
  std::string proto_path = tombstone_file.value() + ".pb";

  struct stat proto_fd_st;
  struct stat proto_file_st;
  ASSERT_EQ(0, fstat(proto_fd.get(), &proto_fd_st));
  ASSERT_EQ(0, stat(proto_path.c_str(), &proto_file_st));

  ASSERT_EQ(proto_fd_st.st_dev, proto_file_st.st_dev);
  ASSERT_EQ(proto_fd_st.st_ino, proto_file_st.st_ino);
}

TEST(tombstoned, proto_intercept) {
  const pid_t self = getpid();
  unique_fd intercept_fd, output_fd;

  InterceptResponse response = {};
  tombstoned_intercept(self, &intercept_fd, &output_fd, &response, kDebuggerdTombstone);
  ASSERT_EQ(InterceptStatus::kRegistered, response.status)
      << "Error message: " << response.error_message;

  unique_fd tombstoned_socket, text_fd, proto_fd;
  ASSERT_TRUE(
      tombstoned_connect(self, &tombstoned_socket, &text_fd, &proto_fd, kDebuggerdTombstoneProto));
  ASSERT_TRUE(android::base::WriteStringToFd("foo", text_fd.get()));
  tombstoned_notify_completion(tombstoned_socket.get());

  text_fd.reset();

  std::string output;
  ASSERT_TRUE(android::base::ReadFdToString(output_fd, &output));
  ASSERT_EQ("foo", output);
}

// Verify that when an intercept is present for the main thread, and the signal
// is received on a different thread, the intercept still works.
TEST_F(CrasherTest, intercept_for_main_thread_signal_on_side_thread) {
  StartProcess([]() {
    std::thread thread([]() {
      // Raise the signal on the side thread.
      raise_debugger_signal(kDebuggerdNativeBacktrace);
    });
    thread.join();
    _exit(0);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd, kDebuggerdNativeBacktrace);
  FinishCrasher();
  AssertDeath(0);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
}

static std::string format_pointer(uintptr_t ptr) {
#if defined(__LP64__)
  return android::base::StringPrintf("%08x'%08x", static_cast<uint32_t>(ptr >> 32),
                                     static_cast<uint32_t>(ptr & 0xffffffff));
#else
  return android::base::StringPrintf("%08x", static_cast<uint32_t>(ptr & 0xffffffff));
#endif
}

static std::string format_pointer(void* ptr) {
  return format_pointer(reinterpret_cast<uintptr_t>(ptr));
}

static std::string format_full_pointer(uintptr_t ptr) {
#if defined(__LP64__)
  return android::base::StringPrintf("%016" PRIx64, ptr);
#else
  return android::base::StringPrintf("%08x", ptr);
#endif
}

static std::string format_full_pointer(void* ptr) {
  return format_full_pointer(reinterpret_cast<uintptr_t>(ptr));
}

__attribute__((__noinline__)) int crash_call(uintptr_t ptr) {
  int* crash_ptr = reinterpret_cast<int*>(ptr);
  *crash_ptr = 1;
  return *crash_ptr;
}

// Verify that a fault address before the first map is properly handled.
TEST_F(CrasherTest, fault_address_before_first_map) {
  StartProcess([]() {
    ASSERT_EQ(0, crash_call(0x1024));
    _exit(0);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0+1024)");

  ASSERT_MATCH(result, R"(\nmemory map \(.*\):\n)");

  std::string match_str = android::base::StringPrintf(
      R"(memory map .*:\n--->Fault address falls at %s before any mapped regions\n    )",
      format_pointer(0x1024).c_str());
  ASSERT_MATCH(result, match_str);
}

// Verify that a fault address after the last map is properly handled.
TEST_F(CrasherTest, fault_address_after_last_map) {
  // This makes assumptions about the memory layout that are not true in HWASan
  // processes.
  SKIP_WITH_HWASAN;
  uintptr_t crash_uptr = untag_address(UINTPTR_MAX - 15);
  StartProcess([crash_uptr]() {
    ASSERT_EQ(0, crash_call(crash_uptr));
    _exit(0);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  std::string match_str = R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x)";
  match_str += format_full_pointer(crash_uptr);
  ASSERT_MATCH(result, match_str);

  ASSERT_MATCH(result, R"(\nmemory map \(.*\): \(fault address prefixed with --->\)\n)");

  // Verifies that the fault address error message is at the end of the
  // maps section. To do this, the check below looks for the start of the
  // open files section or the start of the log file section. It's possible
  // for either of these sections to be present after the maps section right
  // now.
  // If the sections move around, this check might need to be modified.
  match_str = android::base::StringPrintf(
      R"(\n--->Fault address falls at %s after any mapped regions\n(---------|\nopen files:))",
      format_pointer(crash_uptr).c_str());
  ASSERT_MATCH(result, match_str);
}

// Verify that a fault address between maps is properly handled.
TEST_F(CrasherTest, fault_address_between_maps) {
  // Create a map before the fork so it will be present in the child.
  void* start_ptr =
      mmap(nullptr, 3 * getpagesize(), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, start_ptr);
  // Add a name to guarantee that this map is distinct and not combined in the map listing.
  EXPECT_EQ(
      prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, start_ptr, 3 * getpagesize(), "debuggerd map start"),
      0);
  // Unmap the page in the middle.
  void* middle_ptr =
      reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(start_ptr) + getpagesize());
  ASSERT_EQ(0, munmap(middle_ptr, getpagesize()));

  StartProcess([middle_ptr]() {
    ASSERT_EQ(0, crash_call(reinterpret_cast<uintptr_t>(middle_ptr)));
    _exit(0);
  });

  // Unmap the two maps.
  ASSERT_EQ(0, munmap(start_ptr, getpagesize()));
  void* end_ptr =
      reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(start_ptr) + 2 * getpagesize());
  ASSERT_EQ(0, munmap(end_ptr, getpagesize()));

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  std::string match_str = R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x)";
  match_str += format_full_pointer(reinterpret_cast<uintptr_t>(middle_ptr));
  ASSERT_MATCH(result, match_str);

  ASSERT_MATCH(result, R"(\nmemory map \(.*\): \(fault address prefixed with --->\)\n)");

  match_str = android::base::StringPrintf(
      R"(    %s.*\n--->Fault address falls at %s between mapped regions\n    %s)",
      format_pointer(start_ptr).c_str(), format_pointer(middle_ptr).c_str(),
      format_pointer(end_ptr).c_str());
  ASSERT_MATCH(result, match_str);
}

// Verify that a fault address happens in the correct map.
TEST_F(CrasherTest, fault_address_in_map) {
  // Create a map before the fork so it will be present in the child.
  void* ptr = mmap(nullptr, getpagesize(), 0, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, ptr);
  // Add a name to guarantee that this map is distinct and not combined in the map listing.
  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, getpagesize(), "debuggerd map"), 0);

  StartProcess([ptr]() {
    ASSERT_EQ(0, crash_call(reinterpret_cast<uintptr_t>(ptr)));
    _exit(0);
  });

  ASSERT_EQ(0, munmap(ptr, getpagesize()));

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  std::string match_str = R"(signal 11 \(SIGSEGV\), code 2 \(SEGV_ACCERR\), fault addr 0x)";
  match_str += format_full_pointer(reinterpret_cast<uintptr_t>(ptr));
  ASSERT_MATCH(result, match_str);

  ASSERT_MATCH(result, R"(\nmemory map \(.*\): \(fault address prefixed with --->\)\n)");

  match_str = android::base::StringPrintf(R"(\n--->%s.*\n)", format_pointer(ptr).c_str());
  ASSERT_MATCH(result, match_str);
}

static constexpr uint32_t kDexData[] = {
    0x0a786564, 0x00383330, 0xc98b3ab8, 0xf3749d94, 0xaecca4d8, 0xffc7b09a, 0xdca9ca7f, 0x5be5deab,
    0x00000220, 0x00000070, 0x12345678, 0x00000000, 0x00000000, 0x0000018c, 0x00000008, 0x00000070,
    0x00000004, 0x00000090, 0x00000002, 0x000000a0, 0x00000000, 0x00000000, 0x00000003, 0x000000b8,
    0x00000001, 0x000000d0, 0x00000130, 0x000000f0, 0x00000122, 0x0000012a, 0x00000132, 0x00000146,
    0x00000151, 0x00000154, 0x00000158, 0x0000016d, 0x00000001, 0x00000002, 0x00000004, 0x00000006,
    0x00000004, 0x00000002, 0x00000000, 0x00000005, 0x00000002, 0x0000011c, 0x00000000, 0x00000000,
    0x00010000, 0x00000007, 0x00000001, 0x00000000, 0x00000000, 0x00000001, 0x00000001, 0x00000000,
    0x00000003, 0x00000000, 0x0000017e, 0x00000000, 0x00010001, 0x00000001, 0x00000173, 0x00000004,
    0x00021070, 0x000e0000, 0x00010001, 0x00000000, 0x00000178, 0x00000001, 0x0000000e, 0x00000001,
    0x3c060003, 0x74696e69, 0x4c06003e, 0x6e69614d, 0x4c12003b, 0x6176616a, 0x6e616c2f, 0x624f2f67,
    0x7463656a, 0x4d09003b, 0x2e6e6961, 0x6176616a, 0x00560100, 0x004c5602, 0x6a4c5b13, 0x2f617661,
    0x676e616c, 0x7274532f, 0x3b676e69, 0x616d0400, 0x01006e69, 0x000e0700, 0x07000103, 0x0000000e,
    0x81000002, 0x01f00480, 0x02880901, 0x0000000c, 0x00000000, 0x00000001, 0x00000000, 0x00000001,
    0x00000008, 0x00000070, 0x00000002, 0x00000004, 0x00000090, 0x00000003, 0x00000002, 0x000000a0,
    0x00000005, 0x00000003, 0x000000b8, 0x00000006, 0x00000001, 0x000000d0, 0x00002001, 0x00000002,
    0x000000f0, 0x00001001, 0x00000001, 0x0000011c, 0x00002002, 0x00000008, 0x00000122, 0x00002003,
    0x00000002, 0x00000173, 0x00002000, 0x00000001, 0x0000017e, 0x00001000, 0x00000001, 0x0000018c,
};

TEST_F(CrasherTest, verify_dex_pc_with_function_name) {
  StartProcess([]() {
    TemporaryDir td;
    std::string tmp_so_name;
    if (!CopySharedLibrary(td.path, &tmp_so_name)) {
      _exit(1);
    }

    // In order to cause libunwindstack to look for this __dex_debug_descriptor
    // move the library to which has a basename of libart.so.
    std::string art_so_name = android::base::Dirname(tmp_so_name) + "/libart.so";
    ASSERT_EQ(0, rename(tmp_so_name.c_str(), art_so_name.c_str()));
    void* handle = dlopen(art_so_name.c_str(), RTLD_NOW | RTLD_LOCAL);
    if (handle == nullptr) {
      _exit(1);
    }

    void* ptr =
        mmap(nullptr, sizeof(kDexData), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    ASSERT_TRUE(ptr != MAP_FAILED);
    memcpy(ptr, kDexData, sizeof(kDexData));
    EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ptr, sizeof(kDexData), "dex"), 0);

    JITCodeEntry dex_entry = {.symfile_addr = reinterpret_cast<uintptr_t>(ptr),
                              .symfile_size = sizeof(kDexData)};

    JITDescriptor* dex_debug =
        reinterpret_cast<JITDescriptor*>(dlsym(handle, "__dex_debug_descriptor"));
    ASSERT_TRUE(dex_debug != nullptr);
    dex_debug->version = 1;
    dex_debug->action_flag = 0;
    dex_debug->relevant_entry = 0;
    dex_debug->first_entry = reinterpret_cast<uintptr_t>(&dex_entry);

    // This sets the magic dex pc value for register 0, using the value
    // of register 1 + 0x102.
    asm(".cfi_escape "
        "0x16 /* DW_CFA_val_expression */, 0, 0x0a /* size */,"
        "0x0c /* DW_OP_const4u */, 0x44, 0x45, 0x58, 0x31, /* magic = 'DEX1' */"
        "0x13 /* DW_OP_drop */,"
        "0x92 /* DW_OP_bregx */, 1, 0x82, 0x02 /* 2-byte SLEB128 */");

    // For each different architecture, set register one to the dex ptr mmap
    // created above. Then do a nullptr dereference to force a crash.
#if defined(__arm__)
    asm volatile(
        "mov r1, %[base]\n"
        "mov r2, #0\n"
        "str r2, [r2]\n"
        : [base] "+r"(ptr)
        :
        : "r1", "r2", "memory");
#elif defined(__aarch64__)
    asm volatile(
        "mov x1, %[base]\n"
        "mov x2, #0\n"
        "str xzr, [x2]\n"
        : [base] "+r"(ptr)
        :
        : "x1", "x2", "memory");
#elif defined(__riscv)
    // TODO: x1 is ra (the link register) on riscv64, so this might have
    // unintended consequences, but we'll need to change the .cfi_escape if so.
    asm volatile(
        "mv x1, %[base]\n"
        "sw zero, 0(zero)\n"
        : [base] "+r"(ptr)
        :
        : "x1", "memory");
#elif defined(__i386__)
    asm volatile(
        "mov %[base], %%ecx\n"
        "movl $0, 0\n"
        : [base] "+r"(ptr)
        :
        : "ecx", "memory");
#elif defined(__x86_64__)
    asm volatile(
        "mov %[base], %%rdx\n"
        "movq $0, 0\n"
        : [base] "+r"(ptr)
        :
        : "rdx", "memory");
#else
#error "Unsupported architecture"
#endif
    _exit(0);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // Verify the process crashed properly.
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0x0*)");

  // Now verify that the dex_pc frame includes a proper function name.
  ASSERT_MATCH(result, R"( \[anon:dex\] \(Main\.\<init\>\+2)");
}

static std::string format_map_pointer(uintptr_t ptr) {
#if defined(__LP64__)
  return android::base::StringPrintf("%08x'%08x", static_cast<uint32_t>(ptr >> 32),
                                     static_cast<uint32_t>(ptr & 0xffffffff));
#else
  return android::base::StringPrintf("%08x", ptr);
#endif
}

// Verify that map data is properly formatted.
TEST_F(CrasherTest, verify_map_format) {
  // Create multiple maps to make sure that the map data is formatted properly.
  void* none_map = mmap(nullptr, getpagesize(), 0, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, none_map);
  // Add names to guarantee that the maps are distinct and not combined in the map listing.
  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, none_map, getpagesize(), "debuggerd map none"),
            0);
  void* r_map = mmap(nullptr, getpagesize(), PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, r_map);
  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, r_map, getpagesize(), "debuggerd map r"), 0);
  void* w_map = mmap(nullptr, getpagesize(), PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, w_map, getpagesize(), "debuggerd map w"), 0);
  ASSERT_NE(MAP_FAILED, w_map);
  void* x_map = mmap(nullptr, getpagesize(), PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  ASSERT_NE(MAP_FAILED, x_map);
  EXPECT_EQ(prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, x_map, getpagesize(), "debuggerd map x"), 0);

  TemporaryFile tf;
  ASSERT_EQ(0x2000, lseek(tf.fd, 0x2000, SEEK_SET));
  char c = 'f';
  ASSERT_EQ(1, write(tf.fd, &c, 1));
  ASSERT_EQ(0x5000, lseek(tf.fd, 0x5000, SEEK_SET));
  ASSERT_EQ(1, write(tf.fd, &c, 1));
  ASSERT_EQ(0, lseek(tf.fd, 0, SEEK_SET));
  void* file_map = mmap(nullptr, 0x3001, PROT_READ, MAP_PRIVATE, tf.fd, 0x2000);
  ASSERT_NE(MAP_FAILED, file_map);

  StartProcess([]() { abort(); });

  ASSERT_EQ(0, munmap(none_map, getpagesize()));
  ASSERT_EQ(0, munmap(r_map, getpagesize()));
  ASSERT_EQ(0, munmap(w_map, getpagesize()));
  ASSERT_EQ(0, munmap(x_map, getpagesize()));
  ASSERT_EQ(0, munmap(file_map, 0x3001));

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  std::string match_str;
  // Verify none.
  match_str = android::base::StringPrintf(
      "    %s-%s ---         0      %x  \\[anon:debuggerd map none\\]\\n",
      format_map_pointer(reinterpret_cast<uintptr_t>(none_map)).c_str(),
      format_map_pointer(reinterpret_cast<uintptr_t>(none_map) + getpagesize() - 1).c_str(),
      getpagesize());
  ASSERT_MATCH(result, match_str);

  // Verify read-only.
  match_str = android::base::StringPrintf(
      "    %s-%s r--         0      %x  \\[anon:debuggerd map r\\]\\n",
      format_map_pointer(reinterpret_cast<uintptr_t>(r_map)).c_str(),
      format_map_pointer(reinterpret_cast<uintptr_t>(r_map) + getpagesize() - 1).c_str(),
      getpagesize());
  ASSERT_MATCH(result, match_str);

  // Verify write-only.
  match_str = android::base::StringPrintf(
      "    %s-%s -w-         0      %x  \\[anon:debuggerd map w\\]\\n",
      format_map_pointer(reinterpret_cast<uintptr_t>(w_map)).c_str(),
      format_map_pointer(reinterpret_cast<uintptr_t>(w_map) + getpagesize() - 1).c_str(),
      getpagesize());
  ASSERT_MATCH(result, match_str);

  // Verify exec-only.
  match_str = android::base::StringPrintf(
      "    %s-%s --x         0      %x  \\[anon:debuggerd map x\\]\\n",
      format_map_pointer(reinterpret_cast<uintptr_t>(x_map)).c_str(),
      format_map_pointer(reinterpret_cast<uintptr_t>(x_map) + getpagesize() - 1).c_str(),
      getpagesize());
  ASSERT_MATCH(result, match_str);

  // Verify file map with non-zero offset and a name.
  match_str = android::base::StringPrintf(
      "    %s-%s r--      2000      4000  %s\\n",
      format_map_pointer(reinterpret_cast<uintptr_t>(file_map)).c_str(),
      format_map_pointer(reinterpret_cast<uintptr_t>(file_map) + 0x3fff).c_str(), tf.path);
  ASSERT_MATCH(result, match_str);
}

// Verify that the tombstone map data is correct.
TEST_F(CrasherTest, verify_header) {
  StartProcess([]() { abort(); });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  std::string match_str = android::base::StringPrintf(
      "Build fingerprint: '%s'\\nRevision: '%s'\\n",
      android::base::GetProperty("ro.build.fingerprint", "unknown").c_str(),
      android::base::GetProperty("ro.revision", "unknown").c_str());
  match_str += android::base::StringPrintf("ABI: '%s'\n", ABI_STRING);
  ASSERT_MATCH(result, match_str);
}

// Verify that the thread header is formatted properly.
TEST_F(CrasherTest, verify_thread_header) {
  void* shared_map =
      mmap(nullptr, sizeof(pid_t), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, shared_map);
  memset(shared_map, 0, sizeof(pid_t));

  StartProcess([&shared_map]() {
    std::atomic_bool tid_written;
    std::thread thread([&tid_written, &shared_map]() {
      pid_t tid = gettid();
      memcpy(shared_map, &tid, sizeof(pid_t));
      tid_written = true;
      volatile bool done = false;
      while (!done)
        ;
    });
    thread.detach();
    while (!tid_written.load(std::memory_order_acquire))
      ;
    abort();
  });

  pid_t primary_pid = crasher_pid;

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  // Read the tid data out.
  pid_t tid;
  memcpy(&tid, shared_map, sizeof(pid_t));
  ASSERT_NE(0, tid);

  ASSERT_EQ(0, munmap(shared_map, sizeof(pid_t)));

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // Verify that there are two headers, one where the tid is "primary_pid"
  // and the other where the tid is "tid".
  std::string match_str = android::base::StringPrintf("pid: %d, tid: %d, name: .*  >>> .* <<<\\n",
                                                      primary_pid, primary_pid);
  ASSERT_MATCH(result, match_str);

  match_str =
      android::base::StringPrintf("pid: %d, tid: %d, name: .*  >>> .* <<<\\n", primary_pid, tid);
  ASSERT_MATCH(result, match_str);
}

// Verify that there is a BuildID present in the map section and set properly.
TEST_F(CrasherTest, verify_build_id) {
  StartProcess([]() { abort(); });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  // Find every /system or /apex lib and verify the BuildID is displayed
  // properly.
  bool found_valid_elf = false;
  std::smatch match;
  std::regex build_id_regex(R"(  ((/system/|/apex/)\S+) \(BuildId: ([^\)]+)\))");
  for (std::string prev_file; std::regex_search(result, match, build_id_regex);
       result = match.suffix()) {
    if (prev_file == match[1]) {
      // Already checked this file.
      continue;
    }

    prev_file = match[1];
    auto elf_memory = unwindstack::Memory::CreateFileMemory(prev_file, 0);
    unwindstack::Elf elf(elf_memory);
    if (!elf.Init() || !elf.valid()) {
      // Skipping invalid elf files.
      continue;
    }
    ASSERT_EQ(match[3], elf.GetPrintableBuildID());

    found_valid_elf = true;
  }
  ASSERT_TRUE(found_valid_elf) << "Did not find any elf files with valid BuildIDs to check.";
}

const char kLogMessage[] = "Should not see this log message.";

// Verify that the logd process does not read the log.
TEST_F(CrasherTest, logd_skips_reading_logs) {
  StartProcess([]() {
    pthread_setname_np(pthread_self(), "logd");
    LOG(INFO) << kLogMessage;
    abort();
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  // logd should not contain our log message.
  ASSERT_NOT_MATCH(result, kLogMessage);
}

// Verify that the logd process does not read the log when the non-main
// thread crashes.
TEST_F(CrasherTest, logd_skips_reading_logs_not_main_thread) {
  StartProcess([]() {
    pthread_setname_np(pthread_self(), "logd");
    LOG(INFO) << kLogMessage;

    std::thread thread([]() {
      pthread_setname_np(pthread_self(), "not_logd_thread");
      // Raise the signal on the side thread.
      raise_debugger_signal(kDebuggerdTombstone);
    });
    thread.join();
    _exit(0);
  });

  unique_fd output_fd;
  StartIntercept(&output_fd, kDebuggerdTombstone);
  FinishCrasher();
  AssertDeath(0);

  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_BACKTRACE_FRAME(result, "raise_debugger_signal");
  ASSERT_NOT_MATCH(result, kLogMessage);
}

// Disable this test since there is a high liklihood that this would
// be flaky since it requires 500 messages being in the log.
TEST_F(CrasherTest, DISABLED_max_log_messages) {
  StartProcess([]() {
    for (size_t i = 0; i < 600; i++) {
      LOG(INFO) << "Message number " << i;
    }
    abort();
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_NOT_MATCH(result, "Message number 99");
  ASSERT_MATCH(result, "Message number 100");
  ASSERT_MATCH(result, "Message number 599");
}

TEST_F(CrasherTest, log_with_newline) {
  StartProcess([]() {
    LOG(INFO) << "This line has a newline.\nThis is on the next line.";
    abort();
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, ":\\s*This line has a newline.");
  ASSERT_MATCH(result, ":\\s*This is on the next line.");
}

TEST_F(CrasherTest, log_with_non_printable_ascii_verify_encoded) {
  static const std::string kEncodedStr =
      "\x5C\x31"
      "\x5C\x32"
      "\x5C\x33"
      "\x5C\x34"
      "\x5C\x35"
      "\x5C\x36"
      "\x5C\x37"
      "\x5C\x31\x30"
      "\x5C\x31\x36"
      "\x5C\x31\x37"
      "\x5C\x32\x30"
      "\x5C\x32\x31"
      "\x5C\x32\x32"
      "\x5C\x32\x33"
      "\x5C\x32\x34"
      "\x5C\x32\x35"
      "\x5C\x32\x36"
      "\x5C\x32\x37"
      "\x5C\x33\x30"
      "\x5C\x33\x31"
      "\x5C\x33\x32"
      "\x5C\x33\x33"
      "\x5C\x33\x34"
      "\x5C\x33\x35"
      "\x5C\x33\x36"
      "\x5C\x33\x37"
      "\x5C\x31\x37\x37"
      "\x5C\x32\x34\x30"
      "\x5C\x32\x36\x30"
      "\x5C\x33\x30\x30"
      "\x5C\x33\x32\x30";
  StartProcess([]() {
    LOG(FATAL) << "Encoded: "
                  "\x1\x2\x3\x4\x5\x6\x7\x8\xe\xf\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b"
                  "\x1c\x1d\x1e\x1f\x7f\xA0\xB0\xC0\xD0 after";
  });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  // Verify the abort message is sanitized properly.
  size_t pos = result.find(std::string("Abort message: 'Encoded: ") + kEncodedStr + " after'");
  EXPECT_TRUE(pos != std::string::npos) << "Couldn't find sanitized abort message: " << result;

  // Make sure that the log message is sanitized properly too.
  EXPECT_TRUE(result.find(std::string("Encoded: ") + kEncodedStr + " after", pos + 1) !=
              std::string::npos)
      << "Couldn't find sanitized log message: " << result;
}

TEST_F(CrasherTest, log_with_with_special_printable_ascii) {
  static const std::string kMsg = "Not encoded: \t\v\f\r\n after";
  StartProcess([]() { LOG(FATAL) << kMsg; });

  unique_fd output_fd;
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  int intercept_result;
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  // Verify the abort message does not remove characters that are UTF8 but
  // are, technically, not printable.
  size_t pos = result.find(std::string("Abort message: '") + kMsg + "'");
  EXPECT_TRUE(pos != std::string::npos) << "Couldn't find abort message: " << result;

  // Make sure that the log message is handled properly too.
  // The logger automatically splits a newline message into two pieces.
  pos = result.find("Not encoded: \t\v\f\r", pos + kMsg.size());
  EXPECT_TRUE(pos != std::string::npos) << "Couldn't find log message: " << result;
  EXPECT_TRUE(result.find(" after", pos + 1) != std::string::npos)
      << "Couldn't find sanitized log message: " << result;
}
