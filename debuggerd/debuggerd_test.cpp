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

#include <err.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include <chrono>
#include <regex>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/properties.h>
#include <android-base/strings.h>
#include <android-base/unique_fd.h>
#include <cutils/sockets.h>
#include <debuggerd/handler.h>
#include <debuggerd/protocol.h>
#include <debuggerd/util.h>
#include <gtest/gtest.h>

using namespace std::chrono_literals;
using android::base::unique_fd;

#if defined(__LP64__)
#define CRASHER_PATH  "/system/xbin/crasher64"
#define ARCH_SUFFIX "64"
#else
#define CRASHER_PATH "/system/xbin/crasher"
#define ARCH_SUFFIX ""
#endif

constexpr char kWaitForGdbKey[] = "debug.debuggerd.wait_for_gdb";

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

#define ASSERT_MATCH(str, pattern)                                              \
  do {                                                                          \
    std::regex r((pattern));                                                    \
    if (!std::regex_search((str), r)) {                                         \
      FAIL() << "regex mismatch: expected " << (pattern) << " in: \n" << (str); \
    }                                                                           \
  } while (0)

class CrasherTest : public ::testing::Test {
 public:
  pid_t crasher_pid = -1;
  bool previous_wait_for_gdb;
  unique_fd crasher_pipe;
  unique_fd intercept_fd;

  CrasherTest();
  ~CrasherTest();

  void StartIntercept(unique_fd* output_fd);

  // Returns -1 if we fail to read a response from tombstoned, otherwise the received return code.
  void FinishIntercept(int* result);

  void StartProcess(std::function<void()> function);
  void StartCrasher(const std::string& crash_type);
  void FinishCrasher();
  void AssertDeath(int signo);
};

CrasherTest::CrasherTest() {
  previous_wait_for_gdb = android::base::GetBoolProperty(kWaitForGdbKey, false);
  android::base::SetProperty(kWaitForGdbKey, "0");
}

CrasherTest::~CrasherTest() {
  if (crasher_pid != -1) {
    kill(crasher_pid, SIGKILL);
    int status;
    waitpid(crasher_pid, &status, WUNTRACED);
  }

  android::base::SetProperty(kWaitForGdbKey, previous_wait_for_gdb ? "1" : "0");
}

void CrasherTest::StartIntercept(unique_fd* output_fd) {
  if (crasher_pid == -1) {
    FAIL() << "crasher hasn't been started";
  }

  intercept_fd.reset(socket_local_client(kTombstonedInterceptSocketName,
                                         ANDROID_SOCKET_NAMESPACE_RESERVED, SOCK_SEQPACKET));
  if (intercept_fd == -1) {
    FAIL() << "failed to contact tombstoned: " << strerror(errno);
  }

  InterceptRequest req = {.pid = crasher_pid };

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

  if (send_fd(intercept_fd.get(), &req, sizeof(req), std::move(output_pipe_write)) != sizeof(req)) {
    FAIL() << "failed to send output fd to tombstoned: " << strerror(errno);
  }
}

void CrasherTest::FinishIntercept(int* result) {
  InterceptResponse response;

  // Timeout for tombstoned intercept is 10 seconds.
  ssize_t rc = TIMEOUT(20, read(intercept_fd.get(), &response, sizeof(response)));
  if (rc == -1) {
    FAIL() << "failed to read response from tombstoned: " << strerror(errno);
  } else if (rc == 0) {
    *result = -1;
  } else if (rc != sizeof(response)) {
    FAIL() << "received packet of unexpected length from tombstoned: expected " << sizeof(response)
           << ", received " << rc;
  } else {
    *result = response.success;
  }
}

void CrasherTest::StartProcess(std::function<void()> function) {
  unique_fd read_pipe;
  unique_fd crasher_read_pipe;
  if (!Pipe(&crasher_read_pipe, &crasher_pipe)) {
    FAIL() << "failed to create pipe: " << strerror(errno);
  }

  crasher_pid = fork();
  if (crasher_pid == -1) {
    FAIL() << "fork failed: " << strerror(errno);
  } else if (crasher_pid == 0) {
    unique_fd devnull(open("/dev/null", O_WRONLY));
    dup2(crasher_read_pipe.get(), STDIN_FILENO);
    dup2(devnull.get(), STDOUT_FILENO);
    dup2(devnull.get(), STDERR_FILENO);
    function();
    _exit(0);
  }
}

void CrasherTest::StartCrasher(const std::string& crash_type) {
  std::string type = "wait-" + crash_type;
  StartProcess([type]() {
    execl(CRASHER_PATH, CRASHER_PATH, type.c_str(), nullptr);
    err(1, "exec failed");
  });
}

void CrasherTest::FinishCrasher() {
  if (crasher_pipe == -1) {
    FAIL() << "crasher pipe uninitialized";
  }

  ssize_t rc = write(crasher_pipe.get(), "\n", 1);
  if (rc == -1) {
    FAIL() << "failed to write to crasher pipe: " << strerror(errno);
  } else if (rc == 0) {
    FAIL() << "crasher pipe was closed";
  }
}

void CrasherTest::AssertDeath(int signo) {
  int status;
  pid_t pid = TIMEOUT(5, waitpid(crasher_pid, &status, 0));
  if (pid != crasher_pid) {
    FAIL() << "failed to wait for crasher: " << strerror(errno);
  }

  if (!WIFSIGNALED(status)) {
    FAIL() << "crasher didn't terminate via a signal";
  }
  ASSERT_EQ(signo, WTERMSIG(status));
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
  StartCrasher("SIGSEGV");
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
  StartCrasher("abort");
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST_F(CrasherTest, signal) {
  int intercept_result;
  unique_fd output_fd;
  StartCrasher("abort");
  StartIntercept(&output_fd);

  // Wait for a bit, or we might end up killing the process before the signal
  // handler even gets a chance to be registered.
  std::this_thread::sleep_for(100ms);
  ASSERT_EQ(0, kill(crasher_pid, SIGSEGV));

  AssertDeath(SIGSEGV);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(signal 11 \(SIGSEGV\), code 0 \(SI_USER\), fault addr --------)");
  ASSERT_MATCH(result, R"(backtrace:)");
}

TEST_F(CrasherTest, abort_message) {
  int intercept_result;
  unique_fd output_fd;
  StartCrasher("smash-stack");
  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);

  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";

  std::string result;
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(Abort message: 'stack corruption detected \(-fstack-protector\)')");
}

TEST_F(CrasherTest, intercept_timeout) {
  int intercept_result;
  unique_fd output_fd;
  StartCrasher("abort");
  StartIntercept(&output_fd);

  // Don't let crasher finish until we timeout.
  FinishIntercept(&intercept_result);

  ASSERT_NE(1, intercept_result) << "tombstoned reported success? (intercept_result = "
                                 << intercept_result << ")";

  FinishCrasher();
  AssertDeath(SIGABRT);
}

TEST_F(CrasherTest, wait_for_gdb) {
  if (!android::base::SetProperty(kWaitForGdbKey, "1")) {
    FAIL() << "failed to enable wait_for_gdb";
  }
  sleep(1);

  StartCrasher("abort");
  FinishCrasher();

  int status;
  ASSERT_EQ(crasher_pid, waitpid(crasher_pid, &status, WUNTRACED));
  ASSERT_TRUE(WIFSTOPPED(status));
  ASSERT_EQ(SIGSTOP, WSTOPSIG(status));

  ASSERT_EQ(0, kill(crasher_pid, SIGCONT));

  AssertDeath(SIGABRT);
}

// wait_for_gdb shouldn't trigger on manually sent signals.
TEST_F(CrasherTest, wait_for_gdb_signal) {
  if (!android::base::SetProperty(kWaitForGdbKey, "1")) {
    FAIL() << "failed to enable wait_for_gdb";
  }

  StartCrasher("abort");
  ASSERT_EQ(0, kill(crasher_pid, SIGSEGV)) << strerror(errno);
  AssertDeath(SIGSEGV);
}

TEST_F(CrasherTest, backtrace) {
  std::string result;
  int intercept_result;
  unique_fd output_fd;
  StartCrasher("abort");
  StartIntercept(&output_fd);

  std::this_thread::sleep_for(500ms);

  sigval val;
  val.sival_int = 1;
  ASSERT_EQ(0, sigqueue(crasher_pid, DEBUGGER_SIGNAL, val)) << strerror(errno);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+  /system/lib)" ARCH_SUFFIX R"(/libc.so \(read\+)");

  int status;
  ASSERT_EQ(0, waitpid(crasher_pid, &status, WNOHANG | WUNTRACED));

  StartIntercept(&output_fd);
  FinishCrasher();
  AssertDeath(SIGABRT);
  FinishIntercept(&intercept_result);
  ASSERT_EQ(1, intercept_result) << "tombstoned reported failure";
  ConsumeFd(std::move(output_fd), &result);
  ASSERT_MATCH(result, R"(#00 pc [0-9a-f]+\s+ /system/lib)" ARCH_SUFFIX R"(/libc.so \(tgkill)");
}

TEST_F(CrasherTest, PR_SET_DUMPABLE_0_crash) {
  StartProcess([]() {
    prctl(PR_SET_DUMPABLE, 0);
    volatile char* null = static_cast<char*>(nullptr);
    *null = '\0';
  });
  AssertDeath(SIGSEGV);
}

TEST_F(CrasherTest, PR_SET_DUMPABLE_0_raise) {
  StartProcess([]() {
    prctl(PR_SET_DUMPABLE, 0);
    raise(SIGUSR1);
  });
  AssertDeath(SIGUSR1);
}
