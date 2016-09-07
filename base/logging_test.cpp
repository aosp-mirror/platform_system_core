/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include "android-base/logging.h"

#include <libgen.h>

#if defined(_WIN32)
#include <signal.h>
#endif

#include <regex>
#include <string>

#include "android-base/file.h"
#include "android-base/stringprintf.h"
#include "android-base/test_utils.h"

#include <gtest/gtest.h>

#ifdef __ANDROID__
#define HOST_TEST(suite, name) TEST(suite, DISABLED_ ## name)
#else
#define HOST_TEST(suite, name) TEST(suite, name)
#endif

class CapturedStderr {
 public:
  CapturedStderr() : old_stderr_(-1) {
    init();
  }

  ~CapturedStderr() {
    reset();
  }

  int fd() const {
    return temp_file_.fd;
  }

 private:
  void init() {
#if defined(_WIN32)
    // On Windows, stderr is often buffered, so make sure it is unbuffered so
    // that we can immediately read back what was written to stderr.
    ASSERT_EQ(0, setvbuf(stderr, NULL, _IONBF, 0));
#endif
    old_stderr_ = dup(STDERR_FILENO);
    ASSERT_NE(-1, old_stderr_);
    ASSERT_NE(-1, dup2(fd(), STDERR_FILENO));
  }

  void reset() {
    ASSERT_NE(-1, dup2(old_stderr_, STDERR_FILENO));
    ASSERT_EQ(0, close(old_stderr_));
    // Note: cannot restore prior setvbuf() setting.
  }

  TemporaryFile temp_file_;
  int old_stderr_;
};

#if defined(_WIN32)
static void ExitSignalAbortHandler(int) {
  _exit(3);
}
#endif

static void SuppressAbortUI() {
#if defined(_WIN32)
  // We really just want to call _set_abort_behavior(0, _CALL_REPORTFAULT) to
  // suppress the Windows Error Reporting dialog box, but that API is not
  // available in the OS-supplied C Runtime, msvcrt.dll, that we currently
  // use (it is available in the Visual Studio C runtime).
  //
  // Instead, we setup a SIGABRT handler, which is called in abort() right
  // before calling Windows Error Reporting. In the handler, we exit the
  // process just like abort() does.
  ASSERT_NE(SIG_ERR, signal(SIGABRT, ExitSignalAbortHandler));
#endif
}

TEST(logging, CHECK) {
  ASSERT_DEATH({SuppressAbortUI(); CHECK(false);}, "Check failed: false ");
  CHECK(true);

  ASSERT_DEATH({SuppressAbortUI(); CHECK_EQ(0, 1);}, "Check failed: 0 == 1 ");
  CHECK_EQ(0, 0);

  ASSERT_DEATH({SuppressAbortUI(); CHECK_STREQ("foo", "bar");},
               R"(Check failed: "foo" == "bar")");
  CHECK_STREQ("foo", "foo");

  // Test whether CHECK() and CHECK_STREQ() have a dangling if with no else.
  bool flag = false;
  if (true)
    CHECK(true);
  else
    flag = true;
  EXPECT_FALSE(flag) << "CHECK macro probably has a dangling if with no else";

  flag = false;
  if (true)
    CHECK_STREQ("foo", "foo");
  else
    flag = true;
  EXPECT_FALSE(flag) << "CHECK_STREQ probably has a dangling if with no else";
}

static std::string make_log_pattern(android::base::LogSeverity severity,
                                    const char* message) {
  static const char* log_characters = "VDIWEF";
  char log_char = log_characters[severity];
  std::string holder(__FILE__);
  return android::base::StringPrintf(
      "%c \\d+-\\d+ \\d+:\\d+:\\d+ \\s*\\d+ \\s*\\d+ %s:\\d+] %s",
      log_char, basename(&holder[0]), message);
}

#define CHECK_LOG_DISABLED(severity) \
  android::base::ScopedLogSeverity sls1(android::base::FATAL); \
  CapturedStderr cap1; \
  LOG(severity) << "foo bar"; \
  ASSERT_EQ(0, lseek(cap1.fd(), 0, SEEK_CUR)); \

#define CHECK_LOG_ENABLED(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  LOG(severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar"); \

static void CheckMessage(const CapturedStderr& cap,
                         android::base::LogSeverity severity, const char* expected) {
  std::string output;
  ASSERT_EQ(0, lseek(cap.fd(), 0, SEEK_SET));
  android::base::ReadFdToString(cap.fd(), &output);

  // We can't usefully check the output of any of these on Windows because we
  // don't have std::regex, but we can at least make sure we printed at least as
  // many characters are in the log message.
  ASSERT_GT(output.length(), strlen(expected));
  ASSERT_NE(nullptr, strstr(output.c_str(), expected)) << output;

#if !defined(_WIN32)
  std::regex message_regex(make_log_pattern(severity, expected));
  ASSERT_TRUE(std::regex_search(output, message_regex)) << output;
#endif
}

TEST(logging, LOG_FATAL) {
  ASSERT_DEATH({SuppressAbortUI(); LOG(FATAL) << "foobar";}, "foobar");
}

TEST(logging, LOG_ERROR_disabled) {
  CHECK_LOG_DISABLED(ERROR);
}

TEST(logging, LOG_ERROR_enabled) {
  CHECK_LOG_ENABLED(ERROR);
}

TEST(logging, LOG_WARNING_disabled) {
  CHECK_LOG_DISABLED(WARNING);
}

TEST(logging, LOG_WARNING_enabled) {
  CHECK_LOG_ENABLED(WARNING);
}

TEST(logging, LOG_INFO_disabled) {
  CHECK_LOG_DISABLED(INFO);
}

TEST(logging, LOG_INFO_enabled) {
  CHECK_LOG_ENABLED(INFO);
}

TEST(logging, LOG_DEBUG_disabled) {
  CHECK_LOG_DISABLED(DEBUG);
}

TEST(logging, LOG_DEBUG_enabled) {
  CHECK_LOG_ENABLED(DEBUG);
}

TEST(logging, LOG_VERBOSE_disabled) {
  CHECK_LOG_DISABLED(VERBOSE);
}

TEST(logging, LOG_VERBOSE_enabled) {
  CHECK_LOG_ENABLED(VERBOSE);
}

TEST(logging, LOG_does_not_clobber_errno) {
  CapturedStderr cap;
  errno = 12345;
  LOG(INFO) << (errno = 67890);
  EXPECT_EQ(12345, errno) << "errno was not restored";

  CheckMessage(cap, android::base::INFO, "67890");
}

TEST(logging, PLOG_does_not_clobber_errno) {
  CapturedStderr cap;
  errno = 12345;
  PLOG(INFO) << (errno = 67890);
  EXPECT_EQ(12345, errno) << "errno was not restored";

  CheckMessage(cap, android::base::INFO, "67890");
}

TEST(logging, LOG_does_not_have_dangling_if) {
  CapturedStderr cap; // So the logging below has no side-effects.

  // Do the test two ways: once where we hypothesize that LOG()'s if
  // will evaluate to true (when severity is high enough) and once when we
  // expect it to evaluate to false (when severity is not high enough).
  bool flag = false;
  if (true)
    LOG(INFO) << "foobar";
  else
    flag = true;

  EXPECT_FALSE(flag) << "LOG macro probably has a dangling if with no else";

  flag = false;
  if (true)
    LOG(VERBOSE) << "foobar";
  else
    flag = true;

  EXPECT_FALSE(flag) << "LOG macro probably has a dangling if with no else";
}

#define CHECK_PLOG(severity) \

#define CHECK_PLOG_DISABLED(severity) \
  android::base::ScopedLogSeverity sls1(android::base::FATAL); \
  CapturedStderr cap1; \
  PLOG(severity) << "foo bar"; \
  ASSERT_EQ(0, lseek(cap1.fd(), 0, SEEK_CUR)); \

#define CHECK_PLOG_ENABLED(severity) \
  android::base::ScopedLogSeverity sls2(android::base::severity); \
  CapturedStderr cap2; \
  errno = ENOENT; \
  PLOG(severity) << "foobar"; \
  CheckMessage(cap2, android::base::severity, "foobar: No such file or directory"); \

TEST(logging, PLOG_ERROR_disabled) {
  CHECK_PLOG_DISABLED(ERROR);
}

TEST(logging, PLOG_ERROR_enabled) {
  CHECK_PLOG_ENABLED(ERROR);
}

TEST(logging, PLOG_WARNING_disabled) {
  CHECK_PLOG_DISABLED(WARNING);
}

TEST(logging, PLOG_WARNING_enabled) {
  CHECK_PLOG_ENABLED(WARNING);
}

TEST(logging, PLOG_INFO_disabled) {
  CHECK_PLOG_DISABLED(INFO);
}

TEST(logging, PLOG_INFO_enabled) {
  CHECK_PLOG_ENABLED(INFO);
}

TEST(logging, PLOG_DEBUG_disabled) {
  CHECK_PLOG_DISABLED(DEBUG);
}

TEST(logging, PLOG_DEBUG_enabled) {
  CHECK_PLOG_ENABLED(DEBUG);
}

TEST(logging, PLOG_VERBOSE_disabled) {
  CHECK_PLOG_DISABLED(VERBOSE);
}

TEST(logging, PLOG_VERBOSE_enabled) {
  CHECK_PLOG_ENABLED(VERBOSE);
}

TEST(logging, UNIMPLEMENTED) {
  std::string expected = android::base::StringPrintf("%s unimplemented ", __PRETTY_FUNCTION__);

  CapturedStderr cap;
  errno = ENOENT;
  UNIMPLEMENTED(ERROR);
  CheckMessage(cap, android::base::ERROR, expected.c_str());
}
