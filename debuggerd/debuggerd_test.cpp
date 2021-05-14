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
#include <malloc.h>
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
#include <string>
#include <thread>

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
#include <gtest/gtest.h>

#include <libminijail.h>
#include <scoped_minijail.h>

#include "debuggerd/handler.h"
#include "protocol.h"
#include "tombstoned/tombstoned.h"
#include "util.h"

using namespace std::chrono_literals;

using android::base::SendFileDescriptors;
using android::base::unique_fd;

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
    if (sigaction(SIGALRM, &new_sigaction, &new_sigaction) != 0) { \
      err(1, "sigaction failed");                                  \
    }                                                              \
    alarm(seconds);                                                \
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

// Enable GWP-ASan at the start of this process. GWP-ASan is enabled using
// process sampling, so we need to ensure we force GWP-ASan on.
__attribute__((constructor)) static void enable_gwp_asan() {
  bool force = true;
  android_mallopt(M_INITIALIZE_GWP_ASAN, &force, sizeof(force));
}

static void tombstoned_intercept(pid_t target_pid, unique_fd* intercept_fd, unique_fd* output_fd,
                                 InterceptStatus* status, DebuggerdDumpType intercept_type) {
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

  InterceptResponse response;
  rc = TEMP_FAILURE_RETRY(read(intercept_fd->get(), &response, sizeof(response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "failed to read response from tombstoned (EOF)";
  } else if (rc != sizeof(response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
           << ", received " << rc;
  }

  *status = response.status;
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

  InterceptStatus status;
  tombstoned_intercept(crasher_pid, &this->intercept_fd, output_fd, &status, intercept_type);
  ASSERT_EQ(InterceptStatus::kRegistered, status);
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
  constexpr size_t read_length = PAGE_SIZE;
  std::string result;

  while (true) {
    size_t offset = result.size();
    result.resize(result.size() + PAGE_SIZE);
    ssize_t rc = TEMP_FAILURE_RETRY(read(fd.get(), &result[offset], read_length));
    if (rc == -1) {
      FAIL() << "read failed: " << strerror(errno);
    } else if (rc == 0) {
      result.resize(result.size() - PAGE_SIZE);
      break;
    }

    result.resize(result.size() - PAGE_SIZE + rc);
  }

  *output = std::move(result);
}

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
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0xdead)");

  if (mte_supported()) {
    // Test that the default TAGGED_ADDR_CTRL value is set.
    ASSERT_MATCH(result, R"(tagged_addr_ctrl: 000000000007fff3)");
  }
}

TEST_F(CrasherTest, tagged_fault_addr) {
#if !defined(__aarch64__)
  GTEST_SKIP() << "Requires aarch64";
#endif
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
      result,
      R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr (0x100000000000dead|0xdead))");
}

// Marked as weak to prevent the compiler from removing the malloc in the caller. In theory, the
// compiler could still clobber the argument register before trapping, but that's unlikely.
__attribute__((weak)) void CrasherTest::Trap(void* ptr ATTRIBUTE_UNUSED) {
  __builtin_trap();
}

TEST_F(CrasherTest, heap_addr_in_register) {
#if defined(__i386__)
  GTEST_SKIP() << "architecture does not pass arguments in registers";
#endif
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
#endif

// Number of iterations required to reliably guarantee a GWP-ASan crash.
// GWP-ASan's sample rate is not truly nondeterministic, it initialises a
// thread-local counter at 2*SampleRate, and decrements on each malloc(). Once
// the counter reaches zero, we provide a sampled allocation. Then, double that
// figure to allow for left/right allocation alignment, as this is done randomly
// without bias.
#define GWP_ASAN_ITERATIONS_TO_ENSURE_CRASH (0x20000)

struct GwpAsanTestParameters {
  size_t alloc_size;
  bool free_before_access;
  int access_offset;
  std::string cause_needle; // Needle to be found in the "Cause: [GWP-ASan]" line.
};

struct GwpAsanCrasherTest : CrasherTest, testing::WithParamInterface<GwpAsanTestParameters> {};

GwpAsanTestParameters gwp_asan_tests[] = {
  {/* alloc_size */ 7, /* free_before_access */ true, /* access_offset */ 0, "Use After Free, 0 bytes into a 7-byte allocation"},
  {/* alloc_size */ 7, /* free_before_access */ true, /* access_offset */ 1, "Use After Free, 1 byte into a 7-byte allocation"},
  {/* alloc_size */ 7, /* free_before_access */ false, /* access_offset */ 16, "Buffer Overflow, 9 bytes right of a 7-byte allocation"},
  {/* alloc_size */ 16, /* free_before_access */ false, /* access_offset */ -1, "Buffer Underflow, 1 byte left of a 16-byte allocation"},
};

INSTANTIATE_TEST_SUITE_P(GwpAsanTests, GwpAsanCrasherTest, testing::ValuesIn(gwp_asan_tests));

TEST_P(GwpAsanCrasherTest, gwp_asan_uaf) {
  if (mte_supported()) {
    // Skip this test on MTE hardware, as MTE will reliably catch these errors
    // instead of GWP-ASan.
    GTEST_SKIP() << "Skipped on MTE.";
  }

  GwpAsanTestParameters params = GetParam();

  int intercept_result;
  unique_fd output_fd;
  StartProcess([&params]() {
    for (unsigned i = 0; i < GWP_ASAN_ITERATIONS_TO_ENSURE_CRASH; ++i) {
      volatile char* p = reinterpret_cast<volatile char*>(malloc(params.alloc_size));
      if (params.free_before_access) free(static_cast<void*>(const_cast<char*>(p)));
      p[params.access_offset] = 42;
      if (!params.free_before_access) free(static_cast<void*>(const_cast<char*>(p)));
    }
  });

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 2 \(SEGV_ACCERR\))");
  ASSERT_MATCH(result, R"(Cause: \[GWP-ASan\]: )" + params.cause_needle);
  if (params.free_before_access) {
    ASSERT_MATCH(result, R"(deallocated by thread .*
      #00 pc)");
  }
  ASSERT_MATCH(result, R"(allocated by thread .*
      #00 pc)");
}

struct SizeParamCrasherTest : CrasherTest, testing::WithParamInterface<size_t> {};

INSTANTIATE_TEST_SUITE_P(Sizes, SizeParamCrasherTest, testing::Values(16, 131072));

TEST_P(SizeParamCrasherTest, mte_uaf) {
#if defined(__aarch64__)
  if (!mte_supported()) {
    GTEST_SKIP() << "Requires MTE";
  }

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

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
  ASSERT_MATCH(result, R"(Cause: \[MTE\]: Use After Free, 0 bytes into a )" +
                           std::to_string(GetParam()) + R"(-byte allocation)");
  ASSERT_MATCH(result, R"(deallocated by thread .*
      #00 pc)");
  ASSERT_MATCH(result, R"(allocated by thread .*
      #00 pc)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_P(SizeParamCrasherTest, mte_oob_uaf) {
#if defined(__aarch64__)
  if (!mte_supported()) {
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
  if (!mte_supported()) {
    GTEST_SKIP() << "Requires MTE";
  }

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

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
  ASSERT_MATCH(result, R"(Cause: \[MTE\]: Buffer Overflow, 0 bytes right of a )" +
                           std::to_string(GetParam()) + R"(-byte allocation)");
  ASSERT_MATCH(result, R"(allocated by thread .*
      #00 pc)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_P(SizeParamCrasherTest, mte_underflow) {
#if defined(__aarch64__)
  if (!mte_supported()) {
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
  ASSERT_MATCH(result, R"(allocated by thread .*
      #00 pc)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

TEST_F(CrasherTest, mte_multiple_causes) {
#if defined(__aarch64__)
  if (!mte_supported()) {
    GTEST_SKIP() << "Requires MTE";
  }

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

  std::string result;
  ConsumeFd(std::move(output_fd), &result);

  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\))");
  ASSERT_MATCH(
      result,
      R"(Note: multiple potential causes for this crash were detected, listing them in decreasing order of probability.)");

  // Adjacent untracked allocations may cause us to see the wrong underflow here (or only
  // overflows), so we can't match explicitly for an underflow message.
  ASSERT_MATCH(result, R"(Cause: \[MTE\]: Buffer Overflow, 0 bytes right of a 16-byte allocation)");
#else
  GTEST_SKIP() << "Requires aarch64";
#endif
}

#if defined(__aarch64__)
static uintptr_t CreateTagMapping() {
  uintptr_t mapping =
      reinterpret_cast<uintptr_t>(mmap(nullptr, getpagesize(), PROT_READ | PROT_WRITE | PROT_MTE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
  if (reinterpret_cast<void*>(mapping) == MAP_FAILED) {
    return 0;
  }
  __asm__ __volatile__(".arch_extension mte; stg %0, [%0]"
                       :
                       : "r"(mapping + (1ULL << 56))
                       : "memory");
  return mapping;
}
#endif

TEST_F(CrasherTest, mte_tag_dump) {
#if defined(__aarch64__)
  if (!mte_supported()) {
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
  AssertDeath(SIGTRAP);
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
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 1 \(SEGV_MAPERR\), fault addr 0xdead)");
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

static pid_t seccomp_fork_impl(void (*prejail)()) {
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

  ScopedMinijail jail{minijail_new()};
  if (!jail) {
    LOG(FATAL) << "failed to create minijail";
  }

  minijail_no_new_privs(jail.get());
  minijail_log_seccomp_filter_failures(jail.get());
  minijail_use_seccomp_filter(jail.get());
  minijail_parse_seccomp_filters_from_fd(jail.get(), tmp_fd.release());

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

__attribute__((noinline)) extern "C" bool raise_debugger_signal(DebuggerdDumpType dump_type) {
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

TEST_F(CrasherTest, seccomp_tombstone) {
  int intercept_result;
  unique_fd output_fd;

  static const auto dump_type = kDebuggerdTombstone;
  StartProcess(
      []() {
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
}

extern "C" void foo() {
  LOG(INFO) << "foo";
  std::this_thread::sleep_for(1s);
}

extern "C" void bar() {
  LOG(INFO) << "bar";
  std::this_thread::sleep_for(1s);
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

TEST_F(CrasherTest, seccomp_crash_logcat) {
  StartProcess([]() { abort(); }, &seccomp_fork);
  FinishCrasher();

  // Make sure we don't get SIGSYS when trying to dump a crash to logcat.
  AssertDeath(SIGABRT);
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
    InterceptStatus status;
    tombstoned_intercept(pid, &intercept_fd, &output_fd, &status, kDebuggerdTombstone);
    ASSERT_EQ(InterceptStatus::kRegistered, status);

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
      InterceptStatus status;
      tombstoned_intercept(pid, &intercept_fd, &output_fd, &status, kDebuggerdTombstone);
      ASSERT_EQ(InterceptStatus::kRegistered, status);

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
      InterceptStatus status;
      tombstoned_intercept(pid, &intercept_fd, &output_fd, &status, kDebuggerdTombstone);
      ASSERT_EQ(InterceptStatus::kRegistered, status);

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

TEST(tombstoned, java_trace_intercept_smoke) {
  // Using a "real" PID is a little dangerous here - if the test fails
  // or crashes, we might end up getting a bogus / unreliable stack
  // trace.
  const pid_t self = getpid();

  unique_fd intercept_fd, output_fd;
  InterceptStatus status;
  tombstoned_intercept(self, &intercept_fd, &output_fd, &status, kDebuggerdJavaBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, status);

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

TEST(tombstoned, multiple_intercepts) {
  const pid_t fake_pid = 1'234'567;
  unique_fd intercept_fd, output_fd;
  InterceptStatus status;
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &status, kDebuggerdJavaBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, status);

  unique_fd intercept_fd_2, output_fd_2;
  tombstoned_intercept(fake_pid, &intercept_fd_2, &output_fd_2, &status, kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kFailedAlreadyRegistered, status);
}

TEST(tombstoned, intercept_any) {
  const pid_t fake_pid = 1'234'567;

  unique_fd intercept_fd, output_fd;
  InterceptStatus status;
  tombstoned_intercept(fake_pid, &intercept_fd, &output_fd, &status, kDebuggerdNativeBacktrace);
  ASSERT_EQ(InterceptStatus::kRegistered, status);

  const char any[] = "any";
  unique_fd tombstoned_socket, input_fd;
  ASSERT_TRUE(tombstoned_connect(fake_pid, &tombstoned_socket, &input_fd, kDebuggerdAnyIntercept));
  ASSERT_TRUE(android::base::WriteFully(input_fd.get(), any, sizeof(any)));
  tombstoned_notify_completion(tombstoned_socket.get());

  char outbuf[sizeof(any)];
  ASSERT_TRUE(android::base::ReadFully(output_fd.get(), outbuf, sizeof(outbuf)));
  ASSERT_STREQ("any", outbuf);
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

static bool CopySharedLibrary(const char* tmp_dir, std::string* tmp_so_name) {
  std::string test_lib(testing::internal::GetArgvs()[0]);
  auto const value = test_lib.find_last_of('/');
  if (value == std::string::npos) {
    test_lib = "./";
  } else {
    test_lib = test_lib.substr(0, value + 1) + "./";
  }
  test_lib += "libcrash_test.so";

  *tmp_so_name = std::string(tmp_dir) + "/libcrash_test.so";
  std::string cp_cmd = android::base::StringPrintf("cp %s %s", test_lib.c_str(), tmp_dir);

  // Copy the shared so to a tempory directory.
  return system(cp_cmd.c_str()) == 0;
}

TEST_F(CrasherTest, unreadable_elf) {
  int intercept_result;
  unique_fd output_fd;
  StartProcess([]() {
    TemporaryDir td;
    std::string tmp_so_name;
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

  // Give tombstoned some time to link the files into place.
  std::this_thread::sleep_for(100ms);

  // Find the tombstone.
  std::optional<std::string> tombstone_file;
  std::unique_ptr<DIR, decltype(&closedir)> dir_h(opendir("/data/tombstones"), closedir);
  ASSERT_TRUE(dir_h != nullptr);
  std::regex tombstone_re("tombstone_\\d+");
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

  ASSERT_TRUE(tombstone_file);
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
  InterceptStatus status;

  tombstoned_intercept(self, &intercept_fd, &output_fd, &status, kDebuggerdTombstone);
  ASSERT_EQ(InterceptStatus::kRegistered, status);

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
