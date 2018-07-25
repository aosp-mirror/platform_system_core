/*
 * Copyright (C) 2013-2016 The Android Open Source Project
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

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#ifdef __ANDROID__  // includes sys/properties.h which does not exist outside
#include <cutils/properties.h>
#endif
#include <gtest/gtest.h>
#include <log/log_event_list.h>
#include <log/log_properties.h>
#include <log/log_transport.h>
#include <log/logprint.h>
#include <private/android_filesystem_config.h>
#include <private/android_logger.h>

#ifndef TEST_PREFIX
#ifdef TEST_LOGGER
#define TEST_PREFIX android_set_log_transport(TEST_LOGGER);
// make sure we always run code despite overrides if compiled for android
#elif defined(__ANDROID__)
#define TEST_PREFIX
#endif
#endif

#if (!defined(USING_LOGGER_DEFAULT) || !defined(USING_LOGGER_LOCAL) || \
     !defined(USING_LOGGER_STDERR))
#ifdef liblog  // a binary clue that we are overriding the test names
// Does not support log reading blocking feature yet
// Does not support LOG_ID_SECURITY (unless we set LOGGER_LOCAL | LOGGER_LOGD)
// Assume some common aspects are tested by USING_LOGGER_DEFAULT:
// Does not need to _retest_ pmsg functionality
// Does not need to _retest_ property handling as it is a higher function
// Does not need to _retest_ event mapping functionality
// Does not need to _retest_ ratelimit
// Does not need to _retest_ logprint
#define USING_LOGGER_LOCAL
#else
#define USING_LOGGER_DEFAULT
#endif
#endif
#ifdef USING_LOGGER_STDERR
#define SUPPORTS_END_TO_END 0
#else
#define SUPPORTS_END_TO_END 1
#endif

// enhanced version of LOG_FAILURE_RETRY to add support for EAGAIN and
// non-syscall libs. Since we are only using this in the emergency of
// a signal to stuff a terminating code into the logs, we will spin rather
// than try a usleep.
#define LOG_FAILURE_RETRY(exp)                                           \
  ({                                                                     \
    typeof(exp) _rc;                                                     \
    do {                                                                 \
      _rc = (exp);                                                       \
    } while (((_rc == -1) && ((errno == EINTR) || (errno == EAGAIN))) || \
             (_rc == -EINTR) || (_rc == -EAGAIN));                       \
    _rc;                                                                 \
  })

TEST(liblog, __android_log_btwrite) {
#ifdef TEST_PREFIX
  TEST_PREFIX
#endif
  int intBuf = 0xDEADBEEF;
  EXPECT_LT(0,
            __android_log_btwrite(0, EVENT_TYPE_INT, &intBuf, sizeof(intBuf)));
  long long longBuf = 0xDEADBEEFA55A5AA5;
  EXPECT_LT(
      0, __android_log_btwrite(0, EVENT_TYPE_LONG, &longBuf, sizeof(longBuf)));
  usleep(1000);
  char Buf[] = "\20\0\0\0DeAdBeEfA55a5aA5";
  EXPECT_LT(0,
            __android_log_btwrite(0, EVENT_TYPE_STRING, Buf, sizeof(Buf) - 1));
  usleep(1000);
}

#if (defined(__ANDROID__) && defined(USING_LOGGER_DEFAULT))
static std::string popenToString(const std::string& command) {
  std::string ret;

  FILE* fp = popen(command.c_str(), "r");
  if (fp) {
    if (!android::base::ReadFdToString(fileno(fp), &ret)) ret = "";
    pclose(fp);
  }
  return ret;
}

#ifndef NO_PSTORE
static bool isPmsgActive() {
  pid_t pid = getpid();

  std::string myPidFds =
      popenToString(android::base::StringPrintf("ls -l /proc/%d/fd", pid));
  if (myPidFds.length() == 0) return true;  // guess it is?

  return std::string::npos != myPidFds.find(" -> /dev/pmsg0");
}
#endif /* NO_PSTORE */

static bool isLogdwActive() {
  std::string logdwSignature =
      popenToString("grep /dev/socket/logdw /proc/net/unix");
  size_t beginning = logdwSignature.find(' ');
  if (beginning == std::string::npos) return true;
  beginning = logdwSignature.find(' ', beginning + 1);
  if (beginning == std::string::npos) return true;
  size_t end = logdwSignature.find(' ', beginning + 1);
  if (end == std::string::npos) return true;
  end = logdwSignature.find(' ', end + 1);
  if (end == std::string::npos) return true;
  end = logdwSignature.find(' ', end + 1);
  if (end == std::string::npos) return true;
  end = logdwSignature.find(' ', end + 1);
  if (end == std::string::npos) return true;
  std::string allLogdwEndpoints = popenToString(
      "grep ' 00000002" + logdwSignature.substr(beginning, end - beginning) +
      " ' /proc/net/unix | " +
      "sed -n 's/.* \\([0-9][0-9]*\\)$/ -> socket:[\\1]/p'");
  if (allLogdwEndpoints.length() == 0) return true;

  // NB: allLogdwEndpoints has some false positives in it, but those
  // strangers do not overlap with the simplistic activities inside this
  // test suite.

  pid_t pid = getpid();

  std::string myPidFds =
      popenToString(android::base::StringPrintf("ls -l /proc/%d/fd", pid));
  if (myPidFds.length() == 0) return true;

  // NB: fgrep with multiple strings is broken in Android
  for (beginning = 0;
       (end = allLogdwEndpoints.find('\n', beginning)) != std::string::npos;
       beginning = end + 1) {
    if (myPidFds.find(allLogdwEndpoints.substr(beginning, end - beginning)) !=
        std::string::npos)
      return true;
  }
  return false;
}

static bool tested__android_log_close;
#endif

TEST(liblog, __android_log_btwrite__android_logger_list_read) {
#if (defined(__ANDROID__) || defined(USING_LOGGER_LOCAL))
#ifdef TEST_PREFIX
  TEST_PREFIX
#endif
  struct logger_list* logger_list;

  pid_t pid = getpid();

  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

  log_time ts(CLOCK_MONOTONIC);
  EXPECT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));
#ifdef USING_LOGGER_DEFAULT
  // Check that we can close and reopen the logger
  bool logdwActiveAfter__android_log_btwrite;
  if (getuid() == AID_ROOT) {
    tested__android_log_close = true;
#ifndef NO_PSTORE
    bool pmsgActiveAfter__android_log_btwrite = isPmsgActive();
    EXPECT_TRUE(pmsgActiveAfter__android_log_btwrite);
#endif /* NO_PSTORE */
    logdwActiveAfter__android_log_btwrite = isLogdwActive();
    EXPECT_TRUE(logdwActiveAfter__android_log_btwrite);
  } else if (!tested__android_log_close) {
    fprintf(stderr, "WARNING: can not test __android_log_close()\n");
  }
  __android_log_close();
  if (getuid() == AID_ROOT) {
#ifndef NO_PSTORE
    bool pmsgActiveAfter__android_log_close = isPmsgActive();
    EXPECT_FALSE(pmsgActiveAfter__android_log_close);
#endif /* NO_PSTORE */
    bool logdwActiveAfter__android_log_close = isLogdwActive();
    EXPECT_FALSE(logdwActiveAfter__android_log_close);
  }
#endif

  log_time ts1(CLOCK_MONOTONIC);
  EXPECT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts1, sizeof(ts1)));
#ifdef USING_LOGGER_DEFAULT
  if (getuid() == AID_ROOT) {
#ifndef NO_PSTORE
    bool pmsgActiveAfter__android_log_btwrite = isPmsgActive();
    EXPECT_TRUE(pmsgActiveAfter__android_log_btwrite);
#endif /* NO_PSTORE */
    logdwActiveAfter__android_log_btwrite = isLogdwActive();
    EXPECT_TRUE(logdwActiveAfter__android_log_btwrite);
  }
#endif
  usleep(1000000);

  int count = 0;
  int second_count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    EXPECT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.len != sizeof(android_log_event_long_t)) ||
        (log_msg.id() != LOG_ID_EVENTS)) {
      continue;
    }

    android_log_event_long_t* eventData;
    eventData = reinterpret_cast<android_log_event_long_t*>(log_msg.msg());

    if (!eventData || (eventData->payload.type != EVENT_TYPE_LONG)) {
      continue;
    }

    log_time tx(reinterpret_cast<char*>(&eventData->payload.data));
    if (ts == tx) {
      ++count;
    } else if (ts1 == tx) {
      ++second_count;
    }
  }

  EXPECT_EQ(SUPPORTS_END_TO_END, count);
  EXPECT_EQ(SUPPORTS_END_TO_END, second_count);

  android_logger_list_close(logger_list);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#if (defined(__ANDROID__) || defined(USING_LOGGER_LOCAL))
static void print_transport(const char* prefix, int logger) {
  static const char orstr[] = " | ";

  if (!prefix) {
    prefix = "";
  }
  if (logger < 0) {
    fprintf(stderr, "%s%s\n", prefix, strerror(-logger));
    return;
  }

  if (logger == LOGGER_DEFAULT) {
    fprintf(stderr, "%sLOGGER_DEFAULT", prefix);
    prefix = orstr;
  }
  if (logger & LOGGER_LOGD) {
    fprintf(stderr, "%sLOGGER_LOGD", prefix);
    prefix = orstr;
  }
  if (logger & LOGGER_KERNEL) {
    fprintf(stderr, "%sLOGGER_KERNEL", prefix);
    prefix = orstr;
  }
  if (logger & LOGGER_NULL) {
    fprintf(stderr, "%sLOGGER_NULL", prefix);
    prefix = orstr;
  }
  if (logger & LOGGER_LOCAL) {
    fprintf(stderr, "%sLOGGER_LOCAL", prefix);
    prefix = orstr;
  }
  if (logger & LOGGER_STDERR) {
    fprintf(stderr, "%sLOGGER_STDERR", prefix);
    prefix = orstr;
  }
  logger &= ~(LOGGER_LOGD | LOGGER_KERNEL | LOGGER_NULL | LOGGER_LOCAL |
              LOGGER_STDERR);
  if (logger) {
    fprintf(stderr, "%s0x%x", prefix, logger);
    prefix = orstr;
  }
  if (prefix == orstr) {
    fprintf(stderr, "\n");
  }
}
#endif

// This test makes little sense standalone, and requires the tests ahead
// and behind us, to make us whole.  We could incorporate a prefix and
// suffix test to make this standalone, but opted to not complicate this.
TEST(liblog, android_set_log_transport) {
#if (defined(__ANDROID__) || defined(USING_LOGGER_LOCAL))
#ifdef TEST_PREFIX
  TEST_PREFIX
#endif

  int logger = android_get_log_transport();
  print_transport("android_get_log_transport = ", logger);
  EXPECT_NE(LOGGER_NULL, logger);

  int ret;
  EXPECT_EQ(LOGGER_NULL, ret = android_set_log_transport(LOGGER_NULL));
  print_transport("android_set_log_transport = ", ret);
  EXPECT_EQ(LOGGER_NULL, ret = android_get_log_transport());
  print_transport("android_get_log_transport = ", ret);

  pid_t pid = getpid();

  struct logger_list* logger_list;
  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

  log_time ts(CLOCK_MONOTONIC);
  EXPECT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));

  usleep(1000000);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    EXPECT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.len != sizeof(android_log_event_long_t)) ||
        (log_msg.id() != LOG_ID_EVENTS)) {
      continue;
    }

    android_log_event_long_t* eventData;
    eventData = reinterpret_cast<android_log_event_long_t*>(log_msg.msg());

    if (!eventData || (eventData->payload.type != EVENT_TYPE_LONG)) {
      continue;
    }

    log_time tx(reinterpret_cast<char*>(&eventData->payload.data));
    if (ts == tx) {
      ++count;
    }
  }

  android_logger_list_close(logger_list);

  EXPECT_EQ(logger, ret = android_set_log_transport(logger));
  print_transport("android_set_log_transport = ", ret);
  EXPECT_EQ(logger, ret = android_get_log_transport());
  print_transport("android_get_log_transport = ", ret);

  // False negative if liblog.__android_log_btwrite__android_logger_list_read
  // fails above, so we will likely succeed. But we will have so many
  // failures elsewhere that it is probably not worthwhile for us to
  // highlight yet another disappointment.
  //
  // We also expect failures in the following tests if the set does not
  // react in an appropriate manner internally, yet passes, so we depend
  // on this test being in the middle of a series of tests performed in
  // the same process.
  EXPECT_EQ(0, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef TEST_PREFIX
static inline uint32_t get4LE(const uint8_t* src) {
  return src[0] | (src[1] << 8) | (src[2] << 16) | (src[3] << 24);
}

static inline uint32_t get4LE(const char* src) {
  return get4LE(reinterpret_cast<const uint8_t*>(src));
}
#endif

static void bswrite_test(const char* message) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  struct logger_list* logger_list;

  pid_t pid = getpid();

  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

#ifdef __ANDROID__
  log_time ts(android_log_clockid());
#else
  log_time ts(CLOCK_REALTIME);
#endif

  EXPECT_LT(0, __android_log_bswrite(0, message));
  size_t num_lines = 1, size = 0, length = 0, total = 0;
  const char* cp = message;
  while (*cp) {
    if (*cp == '\n') {
      if (cp[1]) {
        ++num_lines;
      }
    } else {
      ++size;
    }
    ++cp;
    ++total;
    ++length;
    if ((LOGGER_ENTRY_MAX_PAYLOAD - 4 - 1 - 4) <= length) {
      break;
    }
  }
  while (*cp) {
    ++cp;
    ++total;
  }
  usleep(1000000);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    EXPECT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.sec < (ts.tv_sec - 1)) ||
        ((ts.tv_sec + 1) < log_msg.entry.sec) ||
        ((size_t)log_msg.entry.len !=
         (sizeof(android_log_event_string_t) + length)) ||
        (log_msg.id() != LOG_ID_EVENTS)) {
      continue;
    }

    android_log_event_string_t* eventData;
    eventData = reinterpret_cast<android_log_event_string_t*>(log_msg.msg());

    if (!eventData || (eventData->type != EVENT_TYPE_STRING)) {
      continue;
    }

    size_t len = get4LE(reinterpret_cast<char*>(&eventData->length));
    if (len == total) {
      ++count;

      AndroidLogFormat* logformat = android_log_format_new();
      EXPECT_TRUE(NULL != logformat);
      AndroidLogEntry entry;
      char msgBuf[1024];
      if (length != total) {
        fprintf(stderr, "Expect \"Binary log entry conversion failed\"\n");
      }
      int processBinaryLogBuffer = android_log_processBinaryLogBuffer(
          &log_msg.entry_v1, &entry, NULL, msgBuf, sizeof(msgBuf));
      EXPECT_EQ((length == total) ? 0 : -1, processBinaryLogBuffer);
      if ((processBinaryLogBuffer == 0) || entry.message) {
        size_t line_overhead = 20;
        if (pid > 99999) ++line_overhead;
        if (pid > 999999) ++line_overhead;
        fflush(stderr);
        if (processBinaryLogBuffer) {
          EXPECT_GT((int)((line_overhead * num_lines) + size),
                    android_log_printLogLine(logformat, fileno(stderr), &entry));
        } else {
          EXPECT_EQ((int)((line_overhead * num_lines) + size),
                    android_log_printLogLine(logformat, fileno(stderr), &entry));
        }
      }
      android_log_format_free(logformat);
    }
  }

  EXPECT_EQ(SUPPORTS_END_TO_END, count);

  android_logger_list_close(logger_list);
#else
  message = NULL;
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, __android_log_bswrite_and_print) {
  bswrite_test("Hello World");
}

TEST(liblog, __android_log_bswrite_and_print__empty_string) {
  bswrite_test("");
}

TEST(liblog, __android_log_bswrite_and_print__newline_prefix) {
  bswrite_test("\nHello World\n");
}

TEST(liblog, __android_log_bswrite_and_print__newline_space_prefix) {
  bswrite_test("\n Hello World \n");
}

TEST(liblog, __android_log_bswrite_and_print__multiple_newline) {
  bswrite_test("one\ntwo\nthree\nfour\nfive\nsix\nseven\neight\nnine\nten");
}

static void buf_write_test(const char* message) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  struct logger_list* logger_list;

  pid_t pid = getpid();

  ASSERT_TRUE(
      NULL !=
      (logger_list = android_logger_list_open(
           LOG_ID_MAIN, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 1000, pid)));

  static const char tag[] = "TEST__android_log_buf_write";
#ifdef __ANDROID__
  log_time ts(android_log_clockid());
#else
  log_time ts(CLOCK_REALTIME);
#endif

  EXPECT_LT(
      0, __android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_INFO, tag, message));
  size_t num_lines = 1, size = 0, length = 0;
  const char* cp = message;
  while (*cp) {
    if (*cp == '\n') {
      if (cp[1]) {
        ++num_lines;
      }
    } else {
      ++size;
    }
    ++length;
    if ((LOGGER_ENTRY_MAX_PAYLOAD - 2 - sizeof(tag)) <= length) {
      break;
    }
    ++cp;
  }
  usleep(1000000);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    ASSERT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.sec < (ts.tv_sec - 1)) ||
        ((ts.tv_sec + 1) < log_msg.entry.sec) ||
        ((size_t)log_msg.entry.len != (sizeof(tag) + length + 2)) ||
        (log_msg.id() != LOG_ID_MAIN)) {
      continue;
    }

    ++count;

    AndroidLogFormat* logformat = android_log_format_new();
    EXPECT_TRUE(NULL != logformat);
    AndroidLogEntry entry;
    int processLogBuffer =
        android_log_processLogBuffer(&log_msg.entry_v1, &entry);
    EXPECT_EQ(0, processLogBuffer);
    if (processLogBuffer == 0) {
      size_t line_overhead = 11;
      if (pid > 99999) ++line_overhead;
      if (pid > 999999) ++line_overhead;
      fflush(stderr);
      EXPECT_EQ((int)(((line_overhead + sizeof(tag)) * num_lines) + size),
                android_log_printLogLine(logformat, fileno(stderr), &entry));
    }
    android_log_format_free(logformat);
  }

  EXPECT_EQ(SUPPORTS_END_TO_END, count);

  android_logger_list_close(logger_list);
#else
  message = NULL;
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, __android_log_buf_write_and_print__empty) {
  buf_write_test("");
}

TEST(liblog, __android_log_buf_write_and_print__newline_prefix) {
  buf_write_test("\nHello World\n");
}

TEST(liblog, __android_log_buf_write_and_print__newline_space_prefix) {
  buf_write_test("\n Hello World \n");
}

#ifndef USING_LOGGER_LOCAL  // requires blocking reader functionality
#ifdef TEST_PREFIX
static unsigned signaled;
static log_time signal_time;

/*
 *  Strictly, we are not allowed to log messages in a signal context, but we
 * do make an effort to keep the failure surface minimized, and this in-effect
 * should catch any regressions in that effort. The odds of a logged message
 * in a signal handler causing a lockup problem should be _very_ small.
 */
static void caught_blocking_signal(int /*signum*/) {
  unsigned long long v = 0xDEADBEEFA55A0000ULL;

  v += getpid() & 0xFFFF;

  ++signaled;
  if ((signal_time.tv_sec == 0) && (signal_time.tv_nsec == 0)) {
    signal_time = log_time(CLOCK_MONOTONIC);
    signal_time.tv_sec += 2;
  }

  LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));
}

// Fill in current process user and system time in 10ms increments
static void get_ticks(unsigned long long* uticks, unsigned long long* sticks) {
  *uticks = *sticks = 0;

  pid_t pid = getpid();

  char buffer[512];
  snprintf(buffer, sizeof(buffer), "/proc/%u/stat", pid);

  FILE* fp = fopen(buffer, "r");
  if (!fp) {
    return;
  }

  char* cp = fgets(buffer, sizeof(buffer), fp);
  fclose(fp);
  if (!cp) {
    return;
  }

  pid_t d;
  char s[sizeof(buffer)];
  char c;
  long long ll;
  unsigned long long ull;

  if (15 != sscanf(buffer,
                   "%d %s %c %lld %lld %lld %lld %lld %llu %llu %llu %llu %llu "
                   "%llu %llu ",
                   &d, s, &c, &ll, &ll, &ll, &ll, &ll, &ull, &ull, &ull, &ull,
                   &ull, uticks, sticks)) {
    *uticks = *sticks = 0;
  }
}
#endif

TEST(liblog, android_logger_list_read__cpu_signal) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  struct logger_list* logger_list;
  unsigned long long v = 0xDEADBEEFA55A0000ULL;

  pid_t pid = getpid();

  v += pid & 0xFFFF;

  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(
                           LOG_ID_EVENTS, ANDROID_LOG_RDONLY, 1000, pid)));

  int count = 0;

  int signals = 0;

  unsigned long long uticks_start;
  unsigned long long sticks_start;
  get_ticks(&uticks_start, &sticks_start);

  const unsigned alarm_time = 10;

  memset(&signal_time, 0, sizeof(signal_time));

  signal(SIGALRM, caught_blocking_signal);
  alarm(alarm_time);

  signaled = 0;

  do {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    alarm(alarm_time);

    ++count;

    ASSERT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.len != sizeof(android_log_event_long_t)) ||
        (log_msg.id() != LOG_ID_EVENTS)) {
      continue;
    }

    android_log_event_long_t* eventData;
    eventData = reinterpret_cast<android_log_event_long_t*>(log_msg.msg());

    if (!eventData || (eventData->payload.type != EVENT_TYPE_LONG)) {
      continue;
    }

    char* cp = reinterpret_cast<char*>(&eventData->payload.data);
    unsigned long long l = cp[0] & 0xFF;
    l |= (unsigned long long)(cp[1] & 0xFF) << 8;
    l |= (unsigned long long)(cp[2] & 0xFF) << 16;
    l |= (unsigned long long)(cp[3] & 0xFF) << 24;
    l |= (unsigned long long)(cp[4] & 0xFF) << 32;
    l |= (unsigned long long)(cp[5] & 0xFF) << 40;
    l |= (unsigned long long)(cp[6] & 0xFF) << 48;
    l |= (unsigned long long)(cp[7] & 0xFF) << 56;

    if (l == v) {
      ++signals;
      break;
    }
  } while (!signaled || (log_time(CLOCK_MONOTONIC) < signal_time));
  alarm(0);
  signal(SIGALRM, SIG_DFL);

  EXPECT_LE(1, count);

  EXPECT_EQ(1, signals);

  android_logger_list_close(logger_list);

  unsigned long long uticks_end;
  unsigned long long sticks_end;
  get_ticks(&uticks_end, &sticks_end);

  // Less than 1% in either user or system time, or both
  const unsigned long long one_percent_ticks = alarm_time;
  unsigned long long user_ticks = uticks_end - uticks_start;
  unsigned long long system_ticks = sticks_end - sticks_start;
  EXPECT_GT(one_percent_ticks, user_ticks);
  EXPECT_GT(one_percent_ticks, system_ticks);
  EXPECT_GT(one_percent_ticks, user_ticks + system_ticks);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef TEST_PREFIX
/*
 *  Strictly, we are not allowed to log messages in a signal context, the
 * correct way to handle this is to ensure the messages are constructed in
 * a thread; the signal handler should only unblock the thread.
 */
static sem_t thread_trigger;

static void caught_blocking_thread(int /*signum*/) {
  sem_post(&thread_trigger);
}

static void* running_thread(void*) {
  unsigned long long v = 0xDEADBEAFA55A0000ULL;

  v += getpid() & 0xFFFF;

  struct timespec timeout;
  clock_gettime(CLOCK_REALTIME, &timeout);
  timeout.tv_sec += 55;
  sem_timedwait(&thread_trigger, &timeout);

  ++signaled;
  if ((signal_time.tv_sec == 0) && (signal_time.tv_nsec == 0)) {
    signal_time = log_time(CLOCK_MONOTONIC);
    signal_time.tv_sec += 2;
  }

  LOG_FAILURE_RETRY(__android_log_btwrite(0, EVENT_TYPE_LONG, &v, sizeof(v)));

  return NULL;
}

static int start_thread() {
  sem_init(&thread_trigger, 0, 0);

  pthread_attr_t attr;
  if (pthread_attr_init(&attr)) {
    return -1;
  }

  struct sched_param param;

  memset(&param, 0, sizeof(param));
  pthread_attr_setschedparam(&attr, &param);
  pthread_attr_setschedpolicy(&attr, SCHED_BATCH);

  if (pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED)) {
    pthread_attr_destroy(&attr);
    return -1;
  }

  pthread_t thread;
  if (pthread_create(&thread, &attr, running_thread, NULL)) {
    pthread_attr_destroy(&attr);
    return -1;
  }

  pthread_attr_destroy(&attr);
  return 0;
}
#endif

TEST(liblog, android_logger_list_read__cpu_thread) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  struct logger_list* logger_list;
  unsigned long long v = 0xDEADBEAFA55A0000ULL;

  pid_t pid = getpid();

  v += pid & 0xFFFF;

  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(
                           LOG_ID_EVENTS, ANDROID_LOG_RDONLY, 1000, pid)));

  int count = 0;

  int signals = 0;

  unsigned long long uticks_start;
  unsigned long long sticks_start;
  get_ticks(&uticks_start, &sticks_start);

  const unsigned alarm_time = 10;

  memset(&signal_time, 0, sizeof(signal_time));

  signaled = 0;
  EXPECT_EQ(0, start_thread());

  signal(SIGALRM, caught_blocking_thread);
  alarm(alarm_time);

  do {
    log_msg log_msg;
    if (LOG_FAILURE_RETRY(android_logger_list_read(logger_list, &log_msg)) <= 0) {
      break;
    }

    alarm(alarm_time);

    ++count;

    ASSERT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.len != sizeof(android_log_event_long_t)) ||
        (log_msg.id() != LOG_ID_EVENTS)) {
      continue;
    }

    android_log_event_long_t* eventData;
    eventData = reinterpret_cast<android_log_event_long_t*>(log_msg.msg());

    if (!eventData || (eventData->payload.type != EVENT_TYPE_LONG)) {
      continue;
    }

    char* cp = reinterpret_cast<char*>(&eventData->payload.data);
    unsigned long long l = cp[0] & 0xFF;
    l |= (unsigned long long)(cp[1] & 0xFF) << 8;
    l |= (unsigned long long)(cp[2] & 0xFF) << 16;
    l |= (unsigned long long)(cp[3] & 0xFF) << 24;
    l |= (unsigned long long)(cp[4] & 0xFF) << 32;
    l |= (unsigned long long)(cp[5] & 0xFF) << 40;
    l |= (unsigned long long)(cp[6] & 0xFF) << 48;
    l |= (unsigned long long)(cp[7] & 0xFF) << 56;

    if (l == v) {
      ++signals;
      break;
    }
  } while (!signaled || (log_time(CLOCK_MONOTONIC) < signal_time));
  alarm(0);
  signal(SIGALRM, SIG_DFL);

  EXPECT_LE(1, count);

  EXPECT_EQ(1, signals);

  android_logger_list_close(logger_list);

  unsigned long long uticks_end;
  unsigned long long sticks_end;
  get_ticks(&uticks_end, &sticks_end);

  // Less than 1% in either user or system time, or both
  const unsigned long long one_percent_ticks = alarm_time;
  unsigned long long user_ticks = uticks_end - uticks_start;
  unsigned long long system_ticks = sticks_end - sticks_start;
  EXPECT_GT(one_percent_ticks, user_ticks);
  EXPECT_GT(one_percent_ticks, system_ticks);
  EXPECT_GT(one_percent_ticks, user_ticks + system_ticks);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
#endif  // !USING_LOGGER_LOCAL

#ifdef TEST_PREFIX
static const char max_payload_tag[] = "TEST_max_payload_and_longish_tag_XXXX";
#define SIZEOF_MAX_PAYLOAD_BUF \
  (LOGGER_ENTRY_MAX_PAYLOAD - sizeof(max_payload_tag) - 1)
#endif
static const char max_payload_buf[] =
    "LEONATO\n\
I learn in this letter that Don Peter of Arragon\n\
comes this night to Messina\n\
MESSENGER\n\
He is very near by this: he was not three leagues off\n\
when I left him\n\
LEONATO\n\
How many gentlemen have you lost in this action?\n\
MESSENGER\n\
But few of any sort, and none of name\n\
LEONATO\n\
A victory is twice itself when the achiever brings\n\
home full numbers. I find here that Don Peter hath\n\
bestowed much honour on a young Florentine called Claudio\n\
MESSENGER\n\
Much deserved on his part and equally remembered by\n\
Don Pedro: he hath borne himself beyond the\n\
promise of his age, doing, in the figure of a lamb,\n\
the feats of a lion: he hath indeed better\n\
bettered expectation than you must expect of me to\n\
tell you how\n\
LEONATO\n\
He hath an uncle here in Messina will be very much\n\
glad of it.\n\
MESSENGER\n\
I have already delivered him letters, and there\n\
appears much joy in him; even so much that joy could\n\
not show itself modest enough without a badge of\n\
bitterness.\n\
LEONATO\n\
Did he break out into tears?\n\
MESSENGER\n\
In great measure.\n\
LEONATO\n\
A kind overflow of kindness: there are no faces\n\
truer than those that are so washed. How much\n\
better is it to weep at joy than to joy at weeping!\n\
BEATRICE\n\
I pray you, is Signior Mountanto returned from the\n\
wars or no?\n\
MESSENGER\n\
I know none of that name, lady: there was none such\n\
in the army of any sort.\n\
LEONATO\n\
What is he that you ask for, niece?\n\
HERO\n\
My cousin means Signior Benedick of Padua.\n\
MESSENGER\n\
O, he's returned; and as pleasant as ever he was.\n\
BEATRICE\n\
He set up his bills here in Messina and challenged\n\
Cupid at the flight; and my uncle's fool, reading\n\
the challenge, subscribed for Cupid, and challenged\n\
him at the bird-bolt. I pray you, how many hath he\n\
killed and eaten in these wars? But how many hath\n\
he killed? for indeed I promised to eat all of his killing.\n\
LEONATO\n\
Faith, niece, you tax Signior Benedick too much;\n\
but he'll be meet with you, I doubt it not.\n\
MESSENGER\n\
He hath done good service, lady, in these wars.\n\
BEATRICE\n\
You had musty victual, and he hath holp to eat it:\n\
he is a very valiant trencherman; he hath an\n\
excellent stomach.\n\
MESSENGER\n\
And a good soldier too, lady.\n\
BEATRICE\n\
And a good soldier to a lady: but what is he to a lord?\n\
MESSENGER\n\
A lord to a lord, a man to a man; stuffed with all\n\
honourable virtues.\n\
BEATRICE\n\
It is so, indeed; he is no less than a stuffed man:\n\
but for the stuffing,--well, we are all mortal.\n\
LEONATO\n\
You must not, sir, mistake my niece. There is a\n\
kind of merry war betwixt Signior Benedick and her:\n\
they never meet but there's a skirmish of wit\n\
between them.\n\
BEATRICE\n\
Alas! he gets nothing by that. In our last\n\
conflict four of his five wits went halting off, and\n\
now is the whole man governed with one: so that if\n\
he have wit enough to keep himself warm, let him\n\
bear it for a difference between himself and his\n\
horse; for it is all the wealth that he hath left,\n\
to be known a reasonable creature. Who is his\n\
companion now? He hath every month a new sworn brother.\n\
MESSENGER\n\
Is't possible?\n\
BEATRICE\n\
Very easily possible: he wears his faith but as\n\
the fashion of his hat; it ever changes with the\n\
next block.\n\
MESSENGER\n\
I see, lady, the gentleman is not in your books.\n\
BEATRICE\n\
No; an he were, I would burn my study. But, I pray\n\
you, who is his companion? Is there no young\n\
squarer now that will make a voyage with him to the devil?\n\
MESSENGER\n\
He is most in the company of the right noble Claudio.\n\
BEATRICE\n\
O Lord, he will hang upon him like a disease: he\n\
is sooner caught than the pestilence, and the taker\n\
runs presently mad. God help the noble Claudio! if\n\
he have caught the Benedick, it will cost him a\n\
thousand pound ere a' be cured.\n\
MESSENGER\n\
I will hold friends with you, lady.\n\
BEATRICE\n\
Do, good friend.\n\
LEONATO\n\
You will never run mad, niece.\n\
BEATRICE\n\
No, not till a hot January.\n\
MESSENGER\n\
Don Pedro is approached.\n\
Enter DON PEDRO, DON JOHN, CLAUDIO, BENEDICK, and BALTHASAR\n\
\n\
DON PEDRO\n\
Good Signior Leonato, you are come to meet your\n\
trouble: the fashion of the world is to avoid\n\
cost, and you encounter it\n\
LEONATO\n\
Never came trouble to my house in the likeness of your grace,\n\
for trouble being gone, comfort should remain, but\n\
when you depart from me, sorrow abides and happiness\n\
takes his leave.";

TEST(liblog, max_payload) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  pid_t pid = getpid();
  char tag[sizeof(max_payload_tag)];
  memcpy(tag, max_payload_tag, sizeof(tag));
  snprintf(tag + sizeof(tag) - 5, 5, "%04X", pid & 0xFFFF);

  LOG_FAILURE_RETRY(__android_log_buf_write(LOG_ID_SYSTEM, ANDROID_LOG_INFO,
                                            tag, max_payload_buf));
  sleep(2);

  struct logger_list* logger_list;

  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(
                           LOG_ID_SYSTEM, ANDROID_LOG_RDONLY, 100, 0)));

  bool matches = false;
  ssize_t max_len = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    if ((log_msg.entry.pid != pid) || (log_msg.id() != LOG_ID_SYSTEM)) {
      continue;
    }

    char* data = log_msg.msg();

    if (!data || strcmp(++data, tag)) {
      continue;
    }

    data += strlen(data) + 1;

    const char* left = data;
    const char* right = max_payload_buf;
    while (*left && *right && (*left == *right)) {
      ++left;
      ++right;
    }

    if (max_len <= (left - data)) {
      max_len = left - data + 1;
    }

    if (max_len > 512) {
      matches = true;
      break;
    }
  }

  android_logger_list_close(logger_list);

#if SUPPORTS_END_TO_END
  EXPECT_EQ(true, matches);

  EXPECT_LE(SIZEOF_MAX_PAYLOAD_BUF, static_cast<size_t>(max_len));
#else
  EXPECT_EQ(false, matches);
#endif
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, __android_log_buf_print__maxtag) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  struct logger_list* logger_list;

  pid_t pid = getpid();

  ASSERT_TRUE(
      NULL !=
      (logger_list = android_logger_list_open(
           LOG_ID_MAIN, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 1000, pid)));

#ifdef __ANDROID__
  log_time ts(android_log_clockid());
#else
  log_time ts(CLOCK_REALTIME);
#endif

  EXPECT_LT(0, __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_INFO,
                                       max_payload_buf, max_payload_buf));
  usleep(1000000);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    ASSERT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.sec < (ts.tv_sec - 1)) ||
        ((ts.tv_sec + 1) < log_msg.entry.sec) ||
        ((size_t)log_msg.entry.len < LOGGER_ENTRY_MAX_PAYLOAD) ||
        (log_msg.id() != LOG_ID_MAIN)) {
      continue;
    }

    ++count;

    AndroidLogFormat* logformat = android_log_format_new();
    EXPECT_TRUE(NULL != logformat);
    AndroidLogEntry entry;
    int processLogBuffer =
        android_log_processLogBuffer(&log_msg.entry_v1, &entry);
    EXPECT_EQ(0, processLogBuffer);
    if (processLogBuffer == 0) {
      fflush(stderr);
      int printLogLine =
          android_log_printLogLine(logformat, fileno(stderr), &entry);
      // Legacy tag truncation
      EXPECT_LE(128, printLogLine);
      // Measured maximum if we try to print part of the tag as message
      EXPECT_GT(LOGGER_ENTRY_MAX_PAYLOAD * 13 / 8, printLogLine);
    }
    android_log_format_free(logformat);
  }

  EXPECT_EQ(SUPPORTS_END_TO_END, count);

  android_logger_list_close(logger_list);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, too_big_payload) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  pid_t pid = getpid();
  static const char big_payload_tag[] = "TEST_big_payload_XXXX";
  char tag[sizeof(big_payload_tag)];
  memcpy(tag, big_payload_tag, sizeof(tag));
  snprintf(tag + sizeof(tag) - 5, 5, "%04X", pid & 0xFFFF);

  std::string longString(3266519, 'x');

  ssize_t ret = LOG_FAILURE_RETRY(__android_log_buf_write(
      LOG_ID_SYSTEM, ANDROID_LOG_INFO, tag, longString.c_str()));

  struct logger_list* logger_list;

  ASSERT_TRUE(NULL != (logger_list = android_logger_list_open(
                           LOG_ID_SYSTEM,
                           ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 100, 0)));

  ssize_t max_len = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    if ((log_msg.entry.pid != pid) || (log_msg.id() != LOG_ID_SYSTEM)) {
      continue;
    }

    char* data = log_msg.msg();

    if (!data || strcmp(++data, tag)) {
      continue;
    }

    data += strlen(data) + 1;

    const char* left = data;
    const char* right = longString.c_str();
    while (*left && *right && (*left == *right)) {
      ++left;
      ++right;
    }

    if (max_len <= (left - data)) {
      max_len = left - data + 1;
    }
  }

  android_logger_list_close(logger_list);

#if !SUPPORTS_END_TO_END
  max_len =
      max_len ? max_len : LOGGER_ENTRY_MAX_PAYLOAD - sizeof(big_payload_tag);
#endif
  EXPECT_LE(LOGGER_ENTRY_MAX_PAYLOAD - sizeof(big_payload_tag),
            static_cast<size_t>(max_len));

  // SLOP: Allow the underlying interface to optionally place a
  // terminating nul at the LOGGER_ENTRY_MAX_PAYLOAD's last byte
  // or not.
  if (ret == (max_len + static_cast<ssize_t>(sizeof(big_payload_tag)) - 1)) {
    --max_len;
  }
  EXPECT_EQ(ret, max_len + static_cast<ssize_t>(sizeof(big_payload_tag)));
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, dual_reader) {
#ifdef TEST_PREFIX
  TEST_PREFIX

  static const int num = 25;

  for (int i = 25; i > 0; --i) {
    static const char fmt[] = "dual_reader %02d";
    char buffer[sizeof(fmt) + 8];
    snprintf(buffer, sizeof(buffer), fmt, i);
    LOG_FAILURE_RETRY(__android_log_buf_write(LOG_ID_MAIN, ANDROID_LOG_INFO,
                                              "liblog", buffer));
  }
  usleep(1000000);

  struct logger_list* logger_list1;
  ASSERT_TRUE(NULL != (logger_list1 = android_logger_list_open(
                           LOG_ID_MAIN,
                           ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, num, 0)));

  struct logger_list* logger_list2;

  if (NULL == (logger_list2 = android_logger_list_open(
                   LOG_ID_MAIN, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   num - 10, 0))) {
    android_logger_list_close(logger_list1);
    ASSERT_TRUE(NULL != logger_list2);
  }

  int count1 = 0;
  bool done1 = false;
  int count2 = 0;
  bool done2 = false;

  do {
    log_msg log_msg;

    if (!done1) {
      if (android_logger_list_read(logger_list1, &log_msg) <= 0) {
        done1 = true;
      } else {
        ++count1;
      }
    }

    if (!done2) {
      if (android_logger_list_read(logger_list2, &log_msg) <= 0) {
        done2 = true;
      } else {
        ++count2;
      }
    }
  } while ((!done1) || (!done2));

  android_logger_list_close(logger_list1);
  android_logger_list_close(logger_list2);

  EXPECT_EQ(num * SUPPORTS_END_TO_END, count1);
  EXPECT_EQ((num - 10) * SUPPORTS_END_TO_END, count2);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef USING_LOGGER_DEFAULT  // Do not retest logprint
static bool checkPriForTag(AndroidLogFormat* p_format, const char* tag,
                           android_LogPriority pri) {
  return android_log_shouldPrintLine(p_format, tag, pri) &&
         !android_log_shouldPrintLine(p_format, tag,
                                      (android_LogPriority)(pri - 1));
}

TEST(liblog, filterRule) {
  static const char tag[] = "random";

  AndroidLogFormat* p_format = android_log_format_new();

  android_log_addFilterRule(p_format, "*:i");

  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_INFO));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) ==
              0);
  android_log_addFilterRule(p_format, "*");
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_DEBUG));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) > 0);
  android_log_addFilterRule(p_format, "*:v");
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_VERBOSE));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) > 0);
  android_log_addFilterRule(p_format, "*:i");
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_INFO));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) ==
              0);

  android_log_addFilterRule(p_format, tag);
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_VERBOSE));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) > 0);
  android_log_addFilterRule(p_format, "random:v");
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_VERBOSE));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) > 0);
  android_log_addFilterRule(p_format, "random:d");
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_DEBUG));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) > 0);
  android_log_addFilterRule(p_format, "random:w");
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_WARN));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) ==
              0);

  android_log_addFilterRule(p_format, "crap:*");
  EXPECT_TRUE(checkPriForTag(p_format, "crap", ANDROID_LOG_VERBOSE));
  EXPECT_TRUE(
      android_log_shouldPrintLine(p_format, "crap", ANDROID_LOG_VERBOSE) > 0);

  // invalid expression
  EXPECT_TRUE(android_log_addFilterRule(p_format, "random:z") < 0);
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_WARN));
  EXPECT_TRUE(android_log_shouldPrintLine(p_format, tag, ANDROID_LOG_DEBUG) ==
              0);

  // Issue #550946
  EXPECT_TRUE(android_log_addFilterString(p_format, " ") == 0);
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_WARN));

  // note trailing space
  EXPECT_TRUE(android_log_addFilterString(p_format, "*:s random:d ") == 0);
  EXPECT_TRUE(checkPriForTag(p_format, tag, ANDROID_LOG_DEBUG));

  EXPECT_TRUE(android_log_addFilterString(p_format, "*:s random:z") < 0);

#if 0  // bitrot, seek update
    char defaultBuffer[512];

    android_log_formatLogLine(p_format,
        defaultBuffer, sizeof(defaultBuffer), 0, ANDROID_LOG_ERROR, 123,
        123, 123, tag, "nofile", strlen("Hello"), "Hello", NULL);

    fprintf(stderr, "%s\n", defaultBuffer);
#endif

  android_log_format_free(p_format);
}
#endif  // USING_LOGGER_DEFAULT

#ifdef USING_LOGGER_DEFAULT  // Do not retest property handling
TEST(liblog, is_loggable) {
#ifdef __ANDROID__
  static const char tag[] = "is_loggable";
  static const char log_namespace[] = "persist.log.tag.";
  static const size_t base_offset = 8; /* skip "persist." */
  // sizeof("string") = strlen("string") + 1
  char key[sizeof(log_namespace) + sizeof(tag) - 1];
  char hold[4][PROP_VALUE_MAX];
  static const struct {
    int level;
    char type;
  } levels[] = {
    { ANDROID_LOG_VERBOSE, 'v' },
    { ANDROID_LOG_DEBUG, 'd' },
    { ANDROID_LOG_INFO, 'i' },
    { ANDROID_LOG_WARN, 'w' },
    { ANDROID_LOG_ERROR, 'e' },
    { ANDROID_LOG_FATAL, 'a' },
    { -1, 's' },
    { -2, 'g' },  // Illegal value, resort to default
  };

  // Set up initial test condition
  memset(hold, 0, sizeof(hold));
  snprintf(key, sizeof(key), "%s%s", log_namespace, tag);
  property_get(key, hold[0], "");
  property_set(key, "");
  property_get(key + base_offset, hold[1], "");
  property_set(key + base_offset, "");
  strcpy(key, log_namespace);
  key[sizeof(log_namespace) - 2] = '\0';
  property_get(key, hold[2], "");
  property_set(key, "");
  property_get(key, hold[3], "");
  property_set(key + base_offset, "");

  // All combinations of level and defaults
  for (size_t i = 0; i < (sizeof(levels) / sizeof(levels[0])); ++i) {
    if (levels[i].level == -2) {
      continue;
    }
    for (size_t j = 0; j < (sizeof(levels) / sizeof(levels[0])); ++j) {
      if (levels[j].level == -2) {
        continue;
      }
      fprintf(stderr, "i=%zu j=%zu\r", i, j);
      bool android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), levels[j].level);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1)) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), levels[j].level));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), levels[j].level));
        }
      }
    }
  }

  // All combinations of level and tag and global properties
  for (size_t i = 0; i < (sizeof(levels) / sizeof(levels[0])); ++i) {
    if (levels[i].level == -2) {
      continue;
    }
    for (size_t j = 0; j < (sizeof(levels) / sizeof(levels[0])); ++j) {
      char buf[2];
      buf[0] = levels[j].type;
      buf[1] = '\0';

      snprintf(key, sizeof(key), "%s%s", log_namespace, tag);
      fprintf(stderr, "i=%zu j=%zu property_set(\"%s\",\"%s\")\r", i, j, key,
              buf);
      usleep(20000);
      property_set(key, buf);
      bool android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1) ||
          ((levels[i].level < ANDROID_LOG_DEBUG) && (levels[j].level == -2))) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      }
      usleep(20000);
      property_set(key, "");

      fprintf(stderr, "i=%zu j=%zu property_set(\"%s\",\"%s\")\r", i, j,
              key + base_offset, buf);
      property_set(key + base_offset, buf);
      android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1) ||
          ((levels[i].level < ANDROID_LOG_DEBUG) && (levels[j].level == -2))) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      }
      usleep(20000);
      property_set(key + base_offset, "");

      strcpy(key, log_namespace);
      key[sizeof(log_namespace) - 2] = '\0';
      fprintf(stderr, "i=%zu j=%zu property_set(\"%s\",\"%s\")\r", i, j, key,
              buf);
      property_set(key, buf);
      android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1) ||
          ((levels[i].level < ANDROID_LOG_DEBUG) && (levels[j].level == -2))) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      }
      usleep(20000);
      property_set(key, "");

      fprintf(stderr, "i=%zu j=%zu property_set(\"%s\",\"%s\")\r", i, j,
              key + base_offset, buf);
      property_set(key + base_offset, buf);
      android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1) ||
          ((levels[i].level < ANDROID_LOG_DEBUG) && (levels[j].level == -2))) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      }
      usleep(20000);
      property_set(key + base_offset, "");
    }
  }

  // All combinations of level and tag properties, but with global set to INFO
  strcpy(key, log_namespace);
  key[sizeof(log_namespace) - 2] = '\0';
  usleep(20000);
  property_set(key, "I");
  snprintf(key, sizeof(key), "%s%s", log_namespace, tag);
  for (size_t i = 0; i < (sizeof(levels) / sizeof(levels[0])); ++i) {
    if (levels[i].level == -2) {
      continue;
    }
    for (size_t j = 0; j < (sizeof(levels) / sizeof(levels[0])); ++j) {
      char buf[2];
      buf[0] = levels[j].type;
      buf[1] = '\0';

      fprintf(stderr, "i=%zu j=%zu property_set(\"%s\",\"%s\")\r", i, j, key,
              buf);
      usleep(20000);
      property_set(key, buf);
      bool android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1) ||
          ((levels[i].level < ANDROID_LOG_INFO)  // Yes INFO
           && (levels[j].level == -2))) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      }
      usleep(20000);
      property_set(key, "");

      fprintf(stderr, "i=%zu j=%zu property_set(\"%s\",\"%s\")\r", i, j,
              key + base_offset, buf);
      property_set(key + base_offset, buf);
      android_log_is_loggable = __android_log_is_loggable_len(
          levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG);
      if ((levels[i].level < levels[j].level) || (levels[j].level == -1) ||
          ((levels[i].level < ANDROID_LOG_INFO)  // Yes INFO
           && (levels[j].level == -2))) {
        if (android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_FALSE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_FALSE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      } else {
        if (!android_log_is_loggable) {
          fprintf(stderr, "\n");
        }
        EXPECT_TRUE(android_log_is_loggable);
        for (size_t k = 10; k; --k) {
          EXPECT_TRUE(__android_log_is_loggable_len(
              levels[i].level, tag, strlen(tag), ANDROID_LOG_DEBUG));
        }
      }
      usleep(20000);
      property_set(key + base_offset, "");
    }
  }

  // reset parms
  snprintf(key, sizeof(key), "%s%s", log_namespace, tag);
  usleep(20000);
  property_set(key, hold[0]);
  property_set(key + base_offset, hold[1]);
  strcpy(key, log_namespace);
  key[sizeof(log_namespace) - 2] = '\0';
  property_set(key, hold[2]);
  property_set(key + base_offset, hold[3]);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
#endif  // USING_LOGGER_DEFAULT

// Following tests the specific issues surrounding error handling wrt logd.
// Kills logd and toss all collected data, equivalent to logcat -b all -c,
// except we also return errors to the logging callers.
#ifdef USING_LOGGER_DEFAULT
#ifdef __ANDROID__
#ifdef TEST_PREFIX
// helper to liblog.enoent to count end-to-end matching logging messages.
static int count_matching_ts(log_time ts) {
  usleep(1000000);

  pid_t pid = getpid();

  struct logger_list* logger_list = android_logger_list_open(
      LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK, 1000, pid);

  int count = 0;
  if (logger_list == NULL) return count;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) break;

    if (log_msg.entry.len != sizeof(android_log_event_long_t)) continue;
    if (log_msg.id() != LOG_ID_EVENTS) continue;

    android_log_event_long_t* eventData;
    eventData = reinterpret_cast<android_log_event_long_t*>(log_msg.msg());
    if (!eventData) continue;
    if (eventData->payload.type != EVENT_TYPE_LONG) continue;

    log_time tx(reinterpret_cast<char*>(&eventData->payload.data));
    if (ts != tx) continue;

    // found event message with matching timestamp signature in payload
    ++count;
  }
  android_logger_list_close(logger_list);

  return count;
}

// meant to be handed to ASSERT_TRUE / EXPECT_TRUE only to expand the message
static testing::AssertionResult IsOk(bool ok, std::string& message) {
  return ok ? testing::AssertionSuccess()
            : (testing::AssertionFailure() << message);
}
#endif  // TEST_PREFIX

TEST(liblog, enoent) {
#ifdef TEST_PREFIX
  TEST_PREFIX
  log_time ts(CLOCK_MONOTONIC);
  EXPECT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));
  EXPECT_EQ(SUPPORTS_END_TO_END, count_matching_ts(ts));

  // This call will fail if we are setuid(AID_SYSTEM), beware of any
  // test prior to this one playing with setuid and causing interference.
  // We need to run before these tests so that they do not interfere with
  // this test.
  //
  // Stopping the logger can affect some other test's expectations as they
  // count on the log buffers filled with existing content, and this
  // effectively does a logcat -c emptying it.  So we want this test to be
  // as near as possible to the bottom of the file.  For example
  // liblog.android_logger_get_ is one of those tests that has no recourse
  // and that would be adversely affected by emptying the log if it was run
  // right after this test.
  if (getuid() != AID_ROOT) {
    fprintf(
        stderr,
        "WARNING: test conditions request being run as root and not AID=%d\n",
        getuid());
    if (!__android_log_is_debuggable()) {
      fprintf(
          stderr,
          "WARNING: can not run test on a \"user\" build, bypassing test\n");
      return;
    }
  }

  system((getuid() == AID_ROOT) ? "stop logd" : "su 0 stop logd");
  usleep(1000000);

  // A clean stop like we are testing returns -ENOENT, but in the _real_
  // world we could get -ENOTCONN or -ECONNREFUSED depending on timing.
  // Alas we can not test these other return values; accept that they
  // are treated equally within the open-retry logic in liblog.
  ts = log_time(CLOCK_MONOTONIC);
  int ret = __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts));
  std::string content = android::base::StringPrintf(
      "__android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)) = %d %s\n",
      ret, (ret <= 0) ? strerror(-ret) : "(content sent)");
  EXPECT_TRUE(
      IsOk((ret == -ENOENT) || (ret == -ENOTCONN) || (ret == -ECONNREFUSED),
           content));
  ret = __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts));
  content = android::base::StringPrintf(
      "__android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)) = %d %s\n",
      ret, (ret <= 0) ? strerror(-ret) : "(content sent)");
  EXPECT_TRUE(
      IsOk((ret == -ENOENT) || (ret == -ENOTCONN) || (ret == -ECONNREFUSED),
           content));
  EXPECT_EQ(0, count_matching_ts(ts));

  system((getuid() == AID_ROOT) ? "start logd" : "su 0 start logd");
  usleep(1000000);

  EXPECT_EQ(0, count_matching_ts(ts));

  ts = log_time(CLOCK_MONOTONIC);
  EXPECT_LT(0, __android_log_btwrite(0, EVENT_TYPE_LONG, &ts, sizeof(ts)));
  EXPECT_EQ(SUPPORTS_END_TO_END, count_matching_ts(ts));

#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
#endif  // __ANDROID__
#endif  // USING_LOGGER_DEFAULT

// Below this point we run risks of setuid(AID_SYSTEM) which may affect others.

// Do not retest properties, and cannot log into LOG_ID_SECURITY
#ifdef USING_LOGGER_DEFAULT
TEST(liblog, __security) {
#ifdef __ANDROID__
  static const char persist_key[] = "persist.logd.security";
  static const char readonly_key[] = "ro.device_owner";
  // A silly default value that can never be in readonly_key so
  // that it can be determined the property is not set.
  static const char nothing_val[] = "_NOTHING_TO_SEE_HERE_";
  char persist[PROP_VALUE_MAX];
  char persist_hold[PROP_VALUE_MAX];
  char readonly[PROP_VALUE_MAX];

  // First part of this test requires the test itself to have the appropriate
  // permissions. If we do not have them, we can not override them, so we
  // bail rather than give a failing grade.
  property_get(persist_key, persist, "");
  fprintf(stderr, "INFO: getprop %s -> %s\n", persist_key, persist);
  strncpy(persist_hold, persist, PROP_VALUE_MAX);
  property_get(readonly_key, readonly, nothing_val);
  fprintf(stderr, "INFO: getprop %s -> %s\n", readonly_key, readonly);

  if (!strcmp(readonly, nothing_val)) {
    // Lets check if we can set the value (we should not be allowed to do so)
    EXPECT_FALSE(__android_log_security());
    fprintf(stderr, "WARNING: setting ro.device_owner to a domain\n");
    static const char domain[] = "com.google.android.SecOps.DeviceOwner";
    EXPECT_NE(0, property_set(readonly_key, domain));
    useconds_t total_time = 0;
    static const useconds_t seconds = 1000000;
    static const useconds_t max_time = 5 * seconds;  // not going to happen
    static const useconds_t rest = 20 * 1000;
    for (; total_time < max_time; total_time += rest) {
      usleep(rest);  // property system does not guarantee performance.
      property_get(readonly_key, readonly, nothing_val);
      if (!strcmp(readonly, domain)) {
        if (total_time > rest) {
          fprintf(stderr, "INFO: took %u.%06u seconds to set property\n",
                  (unsigned)(total_time / seconds),
                  (unsigned)(total_time % seconds));
        }
        break;
      }
    }
    EXPECT_STRNE(domain, readonly);
  }

  if (!strcasecmp(readonly, "false") || !readonly[0] ||
      !strcmp(readonly, nothing_val)) {
    // not enough permissions to run tests surrounding persist.logd.security
    EXPECT_FALSE(__android_log_security());
    return;
  }

  if (!strcasecmp(persist, "true")) {
    EXPECT_TRUE(__android_log_security());
  } else {
    EXPECT_FALSE(__android_log_security());
  }
  property_set(persist_key, "TRUE");
  property_get(persist_key, persist, "");
  uid_t uid = getuid();
  gid_t gid = getgid();
  bool perm = (gid == AID_ROOT) || (uid == AID_ROOT);
  EXPECT_STREQ(perm ? "TRUE" : persist_hold, persist);
  if (!strcasecmp(persist, "true")) {
    EXPECT_TRUE(__android_log_security());
  } else {
    EXPECT_FALSE(__android_log_security());
  }
  property_set(persist_key, "FALSE");
  property_get(persist_key, persist, "");
  EXPECT_STREQ(perm ? "FALSE" : persist_hold, persist);
  if (!strcasecmp(persist, "true")) {
    EXPECT_TRUE(__android_log_security());
  } else {
    EXPECT_FALSE(__android_log_security());
  }
  property_set(persist_key, "true");
  property_get(persist_key, persist, "");
  EXPECT_STREQ(perm ? "true" : persist_hold, persist);
  if (!strcasecmp(persist, "true")) {
    EXPECT_TRUE(__android_log_security());
  } else {
    EXPECT_FALSE(__android_log_security());
  }
  property_set(persist_key, "false");
  property_get(persist_key, persist, "");
  EXPECT_STREQ(perm ? "false" : persist_hold, persist);
  if (!strcasecmp(persist, "true")) {
    EXPECT_TRUE(__android_log_security());
  } else {
    EXPECT_FALSE(__android_log_security());
  }
  property_set(persist_key, "");
  property_get(persist_key, persist, "");
  EXPECT_STREQ(perm ? "" : persist_hold, persist);
  if (!strcasecmp(persist, "true")) {
    EXPECT_TRUE(__android_log_security());
  } else {
    EXPECT_FALSE(__android_log_security());
  }
  property_set(persist_key, persist_hold);
  property_get(persist_key, persist, "");
  EXPECT_STREQ(persist_hold, persist);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, __security_buffer) {
#ifdef __ANDROID__
  struct logger_list* logger_list;
  android_event_long_t buffer;

  static const char persist_key[] = "persist.logd.security";
  char persist[PROP_VALUE_MAX];
  bool set_persist = false;
  bool allow_security = false;

  if (__android_log_security()) {
    allow_security = true;
  } else {
    property_get(persist_key, persist, "");
    if (strcasecmp(persist, "true")) {
      property_set(persist_key, "TRUE");
      if (__android_log_security()) {
        allow_security = true;
        set_persist = true;
      } else {
        property_set(persist_key, persist);
      }
    }
  }

  if (!allow_security) {
    fprintf(stderr,
            "WARNING: "
            "security buffer disabled, bypassing end-to-end test\n");

    log_time ts(CLOCK_MONOTONIC);

    buffer.type = EVENT_TYPE_LONG;
    buffer.data = *(static_cast<uint64_t*>((void*)&ts));

    // expect failure!
    ASSERT_GE(0, __android_log_security_bwrite(0, &buffer, sizeof(buffer)));

    return;
  }

  /* Matches clientHasLogCredentials() in logd */
  uid_t uid = getuid();
  gid_t gid = getgid();
  bool clientHasLogCredentials = true;
  if ((uid != AID_SYSTEM) && (uid != AID_ROOT) && (uid != AID_LOG) &&
      (gid != AID_SYSTEM) && (gid != AID_ROOT) && (gid != AID_LOG)) {
    uid_t euid = geteuid();
    if ((euid != AID_SYSTEM) && (euid != AID_ROOT) && (euid != AID_LOG)) {
      gid_t egid = getegid();
      if ((egid != AID_SYSTEM) && (egid != AID_ROOT) && (egid != AID_LOG)) {
        int num_groups = getgroups(0, NULL);
        if (num_groups > 0) {
          gid_t groups[num_groups];
          num_groups = getgroups(num_groups, groups);
          while (num_groups > 0) {
            if (groups[num_groups - 1] == AID_LOG) {
              break;
            }
            --num_groups;
          }
        }
        if (num_groups <= 0) {
          clientHasLogCredentials = false;
        }
      }
    }
  }
  if (!clientHasLogCredentials) {
    fprintf(stderr,
            "WARNING: "
            "not in system context, bypassing end-to-end test\n");

    log_time ts(CLOCK_MONOTONIC);

    buffer.type = EVENT_TYPE_LONG;
    buffer.data = *(static_cast<uint64_t*>((void*)&ts));

    // expect failure!
    ASSERT_GE(0, __android_log_security_bwrite(0, &buffer, sizeof(buffer)));

    return;
  }

  EXPECT_EQ(0, setuid(AID_SYSTEM));  // only one that can read security buffer

  uid = getuid();
  gid = getgid();
  pid_t pid = getpid();

  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_SECURITY, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

  log_time ts(CLOCK_MONOTONIC);

  buffer.type = EVENT_TYPE_LONG;
  buffer.data = *(static_cast<uint64_t*>((void*)&ts));

  ASSERT_LT(0, __android_log_security_bwrite(0, &buffer, sizeof(buffer)));
  usleep(1000000);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    ASSERT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.len != sizeof(android_log_event_long_t)) ||
        (log_msg.id() != LOG_ID_SECURITY)) {
      continue;
    }

    android_log_event_long_t* eventData;
    eventData = reinterpret_cast<android_log_event_long_t*>(log_msg.msg());

    if (!eventData || (eventData->payload.type != EVENT_TYPE_LONG)) {
      continue;
    }

    log_time tx(reinterpret_cast<char*>(&eventData->payload.data));
    if (ts == tx) {
      ++count;
    }
  }

  if (set_persist) {
    property_set(persist_key, persist);
  }

  android_logger_list_close(logger_list);

  bool clientHasSecurityCredentials = (uid == AID_SYSTEM) || (gid == AID_SYSTEM);
  if (!clientHasSecurityCredentials) {
    fprintf(stderr,
            "WARNING: "
            "not system, content submitted but can not check end-to-end\n");
  }
  EXPECT_EQ(clientHasSecurityCredentials ? 1 : 0, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
#endif  // USING_LOGGER_DEFAULT

#ifdef TEST_PREFIX
static void android_errorWriteWithInfoLog_helper(int TAG, const char* SUBTAG,
                                                 int UID, const char* payload,
                                                 int DATA_LEN, int& count) {
  TEST_PREFIX
  struct logger_list* logger_list;

  pid_t pid = getpid();

  count = 0;

  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

  int retval_android_errorWriteWithinInfoLog =
      android_errorWriteWithInfoLog(TAG, SUBTAG, UID, payload, DATA_LEN);
  if (payload) {
    ASSERT_LT(0, retval_android_errorWriteWithinInfoLog);
  } else {
    ASSERT_GT(0, retval_android_errorWriteWithinInfoLog);
  }

  sleep(2);

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    char* eventData = log_msg.msg();
    if (!eventData) {
      continue;
    }

    char* original = eventData;

    // Tag
    int tag = get4LE(eventData);
    eventData += 4;

    if (tag != TAG) {
      continue;
    }

    if (!payload) {
      // This tag should not have been written because the data was null
      ++count;
      break;
    }

    // List type
    ASSERT_EQ(EVENT_TYPE_LIST, eventData[0]);
    eventData++;

    // Number of elements in list
    ASSERT_EQ(3, eventData[0]);
    eventData++;

    // Element #1: string type for subtag
    ASSERT_EQ(EVENT_TYPE_STRING, eventData[0]);
    eventData++;

    unsigned subtag_len = strlen(SUBTAG);
    if (subtag_len > 32) subtag_len = 32;
    ASSERT_EQ(subtag_len, get4LE(eventData));
    eventData += 4;

    if (memcmp(SUBTAG, eventData, subtag_len)) {
      continue;
    }
    eventData += subtag_len;

    // Element #2: int type for uid
    ASSERT_EQ(EVENT_TYPE_INT, eventData[0]);
    eventData++;

    ASSERT_EQ(UID, (int)get4LE(eventData));
    eventData += 4;

    // Element #3: string type for data
    ASSERT_EQ(EVENT_TYPE_STRING, eventData[0]);
    eventData++;

    size_t dataLen = get4LE(eventData);
    eventData += 4;
    if (DATA_LEN < 512) ASSERT_EQ(DATA_LEN, (int)dataLen);

    if (memcmp(payload, eventData, dataLen)) {
      continue;
    }

    if (DATA_LEN >= 512) {
      eventData += dataLen;
      // 4 bytes for the tag, and max_payload_buf should be truncated.
      ASSERT_LE(4 + 512, eventData - original);       // worst expectations
      ASSERT_GT(4 + DATA_LEN, eventData - original);  // must be truncated
    }

    ++count;
  }

  android_logger_list_close(logger_list);
}
#endif

// Make multiple tests and re-tests orthogonal to prevent falsing.
#ifdef TEST_LOGGER
#define UNIQUE_TAG(X) \
  (0x12340000 + (((X) + sizeof(int) + sizeof(void*)) << 8) + TEST_LOGGER)
#else
#define UNIQUE_TAG(X) \
  (0x12340000 + (((X) + sizeof(int) + sizeof(void*)) << 8) + 0xBA)
#endif

TEST(liblog, android_errorWriteWithInfoLog__android_logger_list_read__typical) {
#ifdef TEST_PREFIX
  int count;
  android_errorWriteWithInfoLog_helper(UNIQUE_TAG(1), "test-subtag", -1,
                                       max_payload_buf, 200, count);
  EXPECT_EQ(SUPPORTS_END_TO_END, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog,
     android_errorWriteWithInfoLog__android_logger_list_read__data_too_large) {
#ifdef TEST_PREFIX
  int count;
  android_errorWriteWithInfoLog_helper(UNIQUE_TAG(2), "test-subtag", -1,
                                       max_payload_buf, sizeof(max_payload_buf),
                                       count);
  EXPECT_EQ(SUPPORTS_END_TO_END, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog,
     android_errorWriteWithInfoLog__android_logger_list_read__null_data) {
#ifdef TEST_PREFIX
  int count;
  android_errorWriteWithInfoLog_helper(UNIQUE_TAG(3), "test-subtag", -1, NULL,
                                       200, count);
  EXPECT_EQ(0, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog,
     android_errorWriteWithInfoLog__android_logger_list_read__subtag_too_long) {
#ifdef TEST_PREFIX
  int count;
  android_errorWriteWithInfoLog_helper(
      UNIQUE_TAG(4), "abcdefghijklmnopqrstuvwxyz now i know my abc", -1,
      max_payload_buf, 200, count);
  EXPECT_EQ(SUPPORTS_END_TO_END, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, __android_log_bswrite_and_print___max) {
  bswrite_test(max_payload_buf);
}

TEST(liblog, __android_log_buf_write_and_print__max) {
  buf_write_test(max_payload_buf);
}

#ifdef TEST_PREFIX
static void android_errorWriteLog_helper(int TAG, const char* SUBTAG,
                                         int& count) {
  TEST_PREFIX
  struct logger_list* logger_list;

  pid_t pid = getpid();

  count = 0;

  // Do a Before and After on the count to measure the effect. Decrement
  // what we find in Before to set the stage.
  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) break;

    char* eventData = log_msg.msg();
    if (!eventData) continue;

    // Tag
    int tag = get4LE(eventData);
    eventData += 4;

    if (tag != TAG) continue;

    if (!SUBTAG) {
      // This tag should not have been written because the data was null
      --count;
      break;
    }

    // List type
    eventData++;
    // Number of elements in list
    eventData++;
    // Element #1: string type for subtag
    eventData++;

    eventData += 4;

    if (memcmp(SUBTAG, eventData, strlen(SUBTAG))) continue;
    --count;
  }

  android_logger_list_close(logger_list);

  // Do an After on the count to measure the effect.
  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

  int retval_android_errorWriteLog = android_errorWriteLog(TAG, SUBTAG);
  if (SUBTAG) {
    ASSERT_LT(0, retval_android_errorWriteLog);
  } else {
    ASSERT_GT(0, retval_android_errorWriteLog);
  }

  sleep(2);

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    char* eventData = log_msg.msg();
    if (!eventData) {
      continue;
    }

    // Tag
    int tag = get4LE(eventData);
    eventData += 4;

    if (tag != TAG) {
      continue;
    }

    if (!SUBTAG) {
      // This tag should not have been written because the data was null
      ++count;
      break;
    }

    // List type
    ASSERT_EQ(EVENT_TYPE_LIST, eventData[0]);
    eventData++;

    // Number of elements in list
    ASSERT_EQ(3, eventData[0]);
    eventData++;

    // Element #1: string type for subtag
    ASSERT_EQ(EVENT_TYPE_STRING, eventData[0]);
    eventData++;

    ASSERT_EQ(strlen(SUBTAG), get4LE(eventData));
    eventData += 4;

    if (memcmp(SUBTAG, eventData, strlen(SUBTAG))) {
      continue;
    }
    ++count;
  }

  android_logger_list_close(logger_list);
}
#endif

TEST(liblog, android_errorWriteLog__android_logger_list_read__success) {
#ifdef TEST_PREFIX
  int count;
  android_errorWriteLog_helper(UNIQUE_TAG(5), "test-subtag", count);
  EXPECT_EQ(SUPPORTS_END_TO_END, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, android_errorWriteLog__android_logger_list_read__null_subtag) {
#ifdef TEST_PREFIX
  int count;
  android_errorWriteLog_helper(UNIQUE_TAG(6), NULL, count);
  EXPECT_EQ(0, count);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

// Do not retest logger list handling
#if (defined(TEST_PREFIX) || !defined(USING_LOGGER_LOCAL))
static int is_real_element(int type) {
  return ((type == EVENT_TYPE_INT) || (type == EVENT_TYPE_LONG) ||
          (type == EVENT_TYPE_STRING) || (type == EVENT_TYPE_FLOAT));
}

static int android_log_buffer_to_string(const char* msg, size_t len,
                                        char* strOut, size_t strOutLen) {
  android_log_context context = create_android_log_parser(msg, len);
  android_log_list_element elem;
  bool overflow = false;
  /* Reserve 1 byte for null terminator. */
  size_t origStrOutLen = strOutLen--;

  if (!context) {
    return -EBADF;
  }

  memset(&elem, 0, sizeof(elem));

  size_t outCount;

  do {
    elem = android_log_read_next(context);
    switch ((int)elem.type) {
      case EVENT_TYPE_LIST:
        if (strOutLen == 0) {
          overflow = true;
        } else {
          *strOut++ = '[';
          strOutLen--;
        }
        break;

      case EVENT_TYPE_LIST_STOP:
        if (strOutLen == 0) {
          overflow = true;
        } else {
          *strOut++ = ']';
          strOutLen--;
        }
        break;

      case EVENT_TYPE_INT:
        /*
         * snprintf also requires room for the null terminator, which
         * we don't care about  but we have allocated enough room for
         * that
         */
        outCount = snprintf(strOut, strOutLen + 1, "%" PRId32, elem.data.int32);
        if (outCount <= strOutLen) {
          strOut += outCount;
          strOutLen -= outCount;
        } else {
          overflow = true;
        }
        break;

      case EVENT_TYPE_LONG:
        /*
         * snprintf also requires room for the null terminator, which
         * we don't care about but we have allocated enough room for
         * that
         */
        outCount = snprintf(strOut, strOutLen + 1, "%" PRId64, elem.data.int64);
        if (outCount <= strOutLen) {
          strOut += outCount;
          strOutLen -= outCount;
        } else {
          overflow = true;
        }
        break;

      case EVENT_TYPE_FLOAT:
        /*
         * snprintf also requires room for the null terminator, which
         * we don't care about but we have allocated enough room for
         * that
         */
        outCount = snprintf(strOut, strOutLen + 1, "%f", elem.data.float32);
        if (outCount <= strOutLen) {
          strOut += outCount;
          strOutLen -= outCount;
        } else {
          overflow = true;
        }
        break;

      default:
        elem.complete = true;
        break;

      case EVENT_TYPE_UNKNOWN:
#if 0  // Ideal purity in the test, we want to complain about UNKNOWN showing up
            if (elem.complete) {
                break;
            }
#endif
        elem.data.string = const_cast<char*>("<unknown>");
        elem.len = strlen(elem.data.string);
      /* FALLTHRU */
      case EVENT_TYPE_STRING:
        if (elem.len <= strOutLen) {
          memcpy(strOut, elem.data.string, elem.len);
          strOut += elem.len;
          strOutLen -= elem.len;
        } else if (strOutLen > 0) {
          /* copy what we can */
          memcpy(strOut, elem.data.string, strOutLen);
          strOut += strOutLen;
          strOutLen = 0;
          overflow = true;
        }
        break;
    }

    if (elem.complete) {
      break;
    }
    /* Determine whether to put a comma or not. */
    if (!overflow &&
        (is_real_element(elem.type) || (elem.type == EVENT_TYPE_LIST_STOP))) {
      android_log_list_element next = android_log_peek_next(context);
      if (!next.complete &&
          (is_real_element(next.type) || (next.type == EVENT_TYPE_LIST))) {
        if (strOutLen == 0) {
          overflow = true;
        } else {
          *strOut++ = ',';
          strOutLen--;
        }
      }
    }
  } while ((elem.type != EVENT_TYPE_UNKNOWN) && !overflow && !elem.complete);

  android_log_destroy(&context);

  if (overflow) {
    if (strOutLen < origStrOutLen) {
      /* leave an indicator */
      *(strOut - 1) = '!';
    } else {
      /* nothing was written at all */
      *strOut++ = '!';
    }
  }
  *strOut++ = '\0';

  if ((elem.type == EVENT_TYPE_UNKNOWN) && !elem.complete) {
    fprintf(stderr, "Binary log entry conversion failed\n");
    return -EINVAL;
  }

  return 0;
}
#endif  // TEST_PREFIX || !USING_LOGGER_LOCAL

#ifdef TEST_PREFIX
static const char* event_test_int32(uint32_t tag, size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  EXPECT_LE(0, android_log_write_int32(ctx, 0x40302010));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);

  return "1076895760";
}

static const char* event_test_int64(uint32_t tag, size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  EXPECT_LE(0, android_log_write_int64(ctx, 0x8070605040302010));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint64_t);

  return "-9191740941672636400";
}

static const char* event_test_list_int64(uint32_t tag, size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int64(ctx, 0x8070605040302010));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) +
                 sizeof(uint8_t) + sizeof(uint64_t);

  return "[-9191740941672636400]";
}

static const char* event_test_simple_automagic_list(uint32_t tag,
                                                    size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  // The convenience API where we allow a simple list to be
  // created without explicit begin or end calls.
  EXPECT_LE(0, android_log_write_int32(ctx, 0x40302010));
  EXPECT_LE(0, android_log_write_int64(ctx, 0x8070605040302010));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) +
                 sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                 sizeof(uint64_t);

  return "[1076895760,-9191740941672636400]";
}

static const char* event_test_list_empty(uint32_t tag, size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t);

  return "[]";
}

static const char* event_test_complex_nested_list(uint32_t tag,
                                                  size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }

  EXPECT_LE(0, android_log_write_list_begin(ctx));  // [
  EXPECT_LE(0, android_log_write_int32(ctx, 0x01020304));
  EXPECT_LE(0, android_log_write_int64(ctx, 0x0102030405060708));
  EXPECT_LE(0, android_log_write_string8(ctx, "Hello World"));
  EXPECT_LE(0, android_log_write_list_begin(ctx));  // [
  EXPECT_LE(0, android_log_write_int32(ctx, 1));
  EXPECT_LE(0, android_log_write_int32(ctx, 2));
  EXPECT_LE(0, android_log_write_int32(ctx, 3));
  EXPECT_LE(0, android_log_write_int32(ctx, 4));
  EXPECT_LE(0, android_log_write_list_end(ctx));  // ]
  EXPECT_LE(0, android_log_write_float32(ctx, 1.0102030405060708));
  EXPECT_LE(0, android_log_write_list_end(ctx));  // ]

  //
  // This one checks for the automagic list creation because a list
  // begin and end was missing for it! This is actually an <oops> corner
  // case, and not the behavior we morally support. The automagic API is to
  // allow for a simple case of a series of objects in a single list. e.g.
  //   int32,int32,int32,string -> [int32,int32,int32,string]
  //
  EXPECT_LE(0, android_log_write_string8(ctx, "dlroW olleH"));

  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) +
                 sizeof(uint8_t) + sizeof(uint8_t) + sizeof(uint8_t) +
                 sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint64_t) +
                 sizeof(uint8_t) + sizeof(uint32_t) + sizeof("Hello World") -
                 1 + sizeof(uint8_t) + sizeof(uint8_t) +
                 4 * (sizeof(uint8_t) + sizeof(uint32_t)) + sizeof(uint8_t) +
                 sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t) +
                 sizeof("dlroW olleH") - 1;

  return "[[16909060,72623859790382856,Hello World,[1,2,3,4],1.010203],dlroW "
         "olleH]";
}

static const char* event_test_7_level_prefix(uint32_t tag,
                                             size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 1));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 2));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 3));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 4));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 5));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 6));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 7));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + 7 * (sizeof(uint8_t) + sizeof(uint8_t) +
                                         sizeof(uint8_t) + sizeof(uint32_t));

  return "[[[[[[[1],2],3],4],5],6],7]";
}

static const char* event_test_7_level_suffix(uint32_t tag,
                                             size_t& expected_len) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(tag)));
  if (!ctx) {
    return NULL;
  }
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 1));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 2));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 3));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 4));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 5));
  EXPECT_LE(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_write_int32(ctx, 6));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list_end(ctx));
  EXPECT_LE(0, android_log_write_list(ctx, LOG_ID_EVENTS));
  EXPECT_LE(0, android_log_destroy(&ctx));
  EXPECT_TRUE(NULL == ctx);

  expected_len = sizeof(uint32_t) + 6 * (sizeof(uint8_t) + sizeof(uint8_t) +
                                         sizeof(uint8_t) + sizeof(uint32_t));

  return "[1,[2,[3,[4,[5,[6]]]]]]";
}

static const char* event_test_android_log_error_write(uint32_t tag,
                                                      size_t& expected_len) {
  EXPECT_LE(
      0, __android_log_error_write(tag, "Hello World", 42, "dlroW olleH", 11));

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) +
                 sizeof(uint8_t) + sizeof(uint32_t) + sizeof("Hello World") -
                 1 + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                 sizeof(uint32_t) + sizeof("dlroW olleH") - 1;

  return "[Hello World,42,dlroW olleH]";
}

static const char* event_test_android_log_error_write_null(uint32_t tag,
                                                           size_t& expected_len) {
  EXPECT_LE(0, __android_log_error_write(tag, "Hello World", 42, NULL, 0));

  expected_len = sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint8_t) +
                 sizeof(uint8_t) + sizeof(uint32_t) + sizeof("Hello World") -
                 1 + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint8_t) +
                 sizeof(uint32_t) + sizeof("") - 1;

  return "[Hello World,42,]";
}

// make sure all user buffers are flushed
static void print_barrier() {
  std::cout.flush();
  fflush(stdout);
  std::cerr.flush();
  fflush(stderr);  // everything else is paranoia ...
}

static void create_android_logger(const char* (*fn)(uint32_t tag,
                                                    size_t& expected_len)) {
  TEST_PREFIX
  struct logger_list* logger_list;

  pid_t pid = getpid();

  ASSERT_TRUE(NULL !=
              (logger_list = android_logger_list_open(
                   LOG_ID_EVENTS, ANDROID_LOG_RDONLY | ANDROID_LOG_NONBLOCK,
                   1000, pid)));

#ifdef __ANDROID__
  log_time ts(android_log_clockid());
#else
  log_time ts(CLOCK_REALTIME);
#endif

  size_t expected_len;
  const char* expected_string = (*fn)(1005, expected_len);

  if (!expected_string) {
    android_logger_list_close(logger_list);
    return;
  }

  usleep(1000000);

  int count = 0;

  for (;;) {
    log_msg log_msg;
    if (android_logger_list_read(logger_list, &log_msg) <= 0) {
      break;
    }

    ASSERT_EQ(log_msg.entry.pid, pid);

    if ((log_msg.entry.sec < (ts.tv_sec - 1)) ||
        ((ts.tv_sec + 1) < log_msg.entry.sec) ||
        ((size_t)log_msg.entry.len != expected_len) ||
        (log_msg.id() != LOG_ID_EVENTS)) {
      continue;
    }

    char* eventData = log_msg.msg();

    ++count;

    AndroidLogFormat* logformat = android_log_format_new();
    EXPECT_TRUE(NULL != logformat);
    AndroidLogEntry entry;
    char msgBuf[1024];
    int processBinaryLogBuffer = android_log_processBinaryLogBuffer(
        &log_msg.entry_v1, &entry, NULL, msgBuf, sizeof(msgBuf));
    EXPECT_EQ(0, processBinaryLogBuffer);
    if (processBinaryLogBuffer == 0) {
      int line_overhead = 20;
      if (pid > 99999) ++line_overhead;
      if (pid > 999999) ++line_overhead;
      print_barrier();
      int printLogLine =
          android_log_printLogLine(logformat, fileno(stderr), &entry);
      print_barrier();
      EXPECT_EQ(line_overhead + (int)strlen(expected_string), printLogLine);
    }
    android_log_format_free(logformat);

    // test buffer reading API
    int buffer_to_string = -1;
    if (eventData) {
      snprintf(msgBuf, sizeof(msgBuf), "I/[%" PRIu32 "]", get4LE(eventData));
      print_barrier();
      fprintf(stderr, "%-10s(%5u): ", msgBuf, pid);
      memset(msgBuf, 0, sizeof(msgBuf));
      buffer_to_string = android_log_buffer_to_string(
          eventData + sizeof(uint32_t), log_msg.entry.len - sizeof(uint32_t),
          msgBuf, sizeof(msgBuf));
      fprintf(stderr, "%s\n", msgBuf);
      print_barrier();
    }
    EXPECT_EQ(0, buffer_to_string);
    EXPECT_EQ(strlen(expected_string), strlen(msgBuf));
    EXPECT_EQ(0, strcmp(expected_string, msgBuf));
  }

  EXPECT_EQ(SUPPORTS_END_TO_END, count);

  android_logger_list_close(logger_list);
}
#endif

TEST(liblog, create_android_logger_int32) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_int32);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_int64) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_int64);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_list_int64) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_list_int64);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_simple_automagic_list) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_simple_automagic_list);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_list_empty) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_list_empty);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_complex_nested_list) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_complex_nested_list);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_7_level_prefix) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_7_level_prefix);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_7_level_suffix) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_7_level_suffix);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_android_log_error_write) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_android_log_error_write);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

TEST(liblog, create_android_logger_android_log_error_write_null) {
#ifdef TEST_PREFIX
  create_android_logger(event_test_android_log_error_write_null);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef USING_LOGGER_DEFAULT  // Do not retest logger list handling
TEST(liblog, create_android_logger_overflow) {
  android_log_context ctx;

  EXPECT_TRUE(NULL != (ctx = create_android_logger(1005)));
  if (ctx) {
    for (size_t i = 0; i < ANDROID_MAX_LIST_NEST_DEPTH; ++i) {
      EXPECT_LE(0, android_log_write_list_begin(ctx));
    }
    EXPECT_GT(0, android_log_write_list_begin(ctx));
    /* One more for good measure, must be permanently unhappy */
    EXPECT_GT(0, android_log_write_list_begin(ctx));
    EXPECT_LE(0, android_log_destroy(&ctx));
    EXPECT_TRUE(NULL == ctx);
  }

  ASSERT_TRUE(NULL != (ctx = create_android_logger(1005)));
  for (size_t i = 0; i < ANDROID_MAX_LIST_NEST_DEPTH; ++i) {
    EXPECT_LE(0, android_log_write_list_begin(ctx));
    EXPECT_LE(0, android_log_write_int32(ctx, i));
  }
  EXPECT_GT(0, android_log_write_list_begin(ctx));
  /* One more for good measure, must be permanently unhappy */
  EXPECT_GT(0, android_log_write_list_begin(ctx));
  EXPECT_LE(0, android_log_destroy(&ctx));
  ASSERT_TRUE(NULL == ctx);
}

TEST(liblog, android_log_write_list_buffer) {
  __android_log_event_list ctx(1005);
  ctx << 1005 << "tag_def"
      << "(tag|1),(name|3),(format|3)";
  std::string buffer(ctx);
  ctx.close();

  char msgBuf[1024];
  memset(msgBuf, 0, sizeof(msgBuf));
  EXPECT_EQ(android_log_buffer_to_string(buffer.data(), buffer.length(), msgBuf,
                                         sizeof(msgBuf)),
            0);
  EXPECT_STREQ(msgBuf, "[1005,tag_def,(tag|1),(name|3),(format|3)]");
}
#endif  // USING_LOGGER_DEFAULT

#ifdef USING_LOGGER_DEFAULT  // Do not retest pmsg functionality
#ifdef __ANDROID__
#ifndef NO_PSTORE
static const char __pmsg_file[] =
    "/data/william-shakespeare/MuchAdoAboutNothing.txt";
#endif /* NO_PSTORE */
#endif

TEST(liblog, __android_log_pmsg_file_write) {
#ifdef __ANDROID__
#ifndef NO_PSTORE
  __android_log_close();
  if (getuid() == AID_ROOT) {
    tested__android_log_close = true;
    bool pmsgActiveAfter__android_log_close = isPmsgActive();
    bool logdwActiveAfter__android_log_close = isLogdwActive();
    EXPECT_FALSE(pmsgActiveAfter__android_log_close);
    EXPECT_FALSE(logdwActiveAfter__android_log_close);
  } else if (!tested__android_log_close) {
    fprintf(stderr, "WARNING: can not test __android_log_close()\n");
  }
  int return__android_log_pmsg_file_write = __android_log_pmsg_file_write(
      LOG_ID_CRASH, ANDROID_LOG_VERBOSE, __pmsg_file, max_payload_buf,
      sizeof(max_payload_buf));
  EXPECT_LT(0, return__android_log_pmsg_file_write);
  if (return__android_log_pmsg_file_write == -ENOMEM) {
    fprintf(stderr,
            "Kernel does not have space allocated to pmsg pstore driver "
            "configured\n");
  } else if (!return__android_log_pmsg_file_write) {
    fprintf(stderr,
            "Reboot, ensure file %s matches\n"
            "with liblog.__android_log_msg_file_read test\n",
            __pmsg_file);
  }
  bool pmsgActiveAfter__android_pmsg_file_write;
  bool logdwActiveAfter__android_pmsg_file_write;
  if (getuid() == AID_ROOT) {
    pmsgActiveAfter__android_pmsg_file_write = isPmsgActive();
    logdwActiveAfter__android_pmsg_file_write = isLogdwActive();
    EXPECT_FALSE(pmsgActiveAfter__android_pmsg_file_write);
    EXPECT_FALSE(logdwActiveAfter__android_pmsg_file_write);
  }
  EXPECT_LT(
      0, __android_log_buf_print(LOG_ID_MAIN, ANDROID_LOG_INFO,
                                 "TEST__android_log_pmsg_file_write", "main"));
  if (getuid() == AID_ROOT) {
    bool pmsgActiveAfter__android_log_buf_print = isPmsgActive();
    bool logdwActiveAfter__android_log_buf_print = isLogdwActive();
    EXPECT_TRUE(pmsgActiveAfter__android_log_buf_print);
    EXPECT_TRUE(logdwActiveAfter__android_log_buf_print);
  }
  EXPECT_LT(0, __android_log_pmsg_file_write(LOG_ID_CRASH, ANDROID_LOG_VERBOSE,
                                             __pmsg_file, max_payload_buf,
                                             sizeof(max_payload_buf)));
  if (getuid() == AID_ROOT) {
    pmsgActiveAfter__android_pmsg_file_write = isPmsgActive();
    logdwActiveAfter__android_pmsg_file_write = isLogdwActive();
    EXPECT_TRUE(pmsgActiveAfter__android_pmsg_file_write);
    EXPECT_TRUE(logdwActiveAfter__android_pmsg_file_write);
  }
#else  /* NO_PSTORE */
  GTEST_LOG_(INFO) << "This test does nothing because of NO_PSTORE.\n";
#endif /* NO_PSTORE */
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}

#ifdef __ANDROID__
#ifndef NO_PSTORE
static ssize_t __pmsg_fn(log_id_t logId, char prio, const char* filename,
                         const char* buf, size_t len, void* arg) {
  EXPECT_TRUE(NULL == arg);
  EXPECT_EQ(LOG_ID_CRASH, logId);
  EXPECT_EQ(ANDROID_LOG_VERBOSE, prio);
  EXPECT_FALSE(NULL == strstr(__pmsg_file, filename));
  EXPECT_EQ(len, sizeof(max_payload_buf));
  EXPECT_EQ(0, strcmp(max_payload_buf, buf));

  ++signaled;
  if ((len != sizeof(max_payload_buf)) || strcmp(max_payload_buf, buf)) {
    fprintf(stderr, "comparison fails on content \"%s\"\n", buf);
  }
  return arg || (LOG_ID_CRASH != logId) || (ANDROID_LOG_VERBOSE != prio) ||
                 !strstr(__pmsg_file, filename) ||
                 (len != sizeof(max_payload_buf)) ||
                 !!strcmp(max_payload_buf, buf)
             ? -ENOEXEC
             : 1;
}
#endif /* NO_PSTORE */
#endif

TEST(liblog, __android_log_pmsg_file_read) {
#ifdef __ANDROID__
#ifndef NO_PSTORE
  signaled = 0;

  __android_log_close();
  if (getuid() == AID_ROOT) {
    tested__android_log_close = true;
    bool pmsgActiveAfter__android_log_close = isPmsgActive();
    bool logdwActiveAfter__android_log_close = isLogdwActive();
    EXPECT_FALSE(pmsgActiveAfter__android_log_close);
    EXPECT_FALSE(logdwActiveAfter__android_log_close);
  } else if (!tested__android_log_close) {
    fprintf(stderr, "WARNING: can not test __android_log_close()\n");
  }

  ssize_t ret = __android_log_pmsg_file_read(LOG_ID_CRASH, ANDROID_LOG_VERBOSE,
                                             __pmsg_file, __pmsg_fn, NULL);

  if (getuid() == AID_ROOT) {
    bool pmsgActiveAfter__android_log_pmsg_file_read = isPmsgActive();
    bool logdwActiveAfter__android_log_pmsg_file_read = isLogdwActive();
    EXPECT_FALSE(pmsgActiveAfter__android_log_pmsg_file_read);
    EXPECT_FALSE(logdwActiveAfter__android_log_pmsg_file_read);
  }

  if (ret == -ENOENT) {
    fprintf(stderr,
            "No pre-boot results of liblog.__android_log_mesg_file_write to "
            "compare with,\n"
            "false positive test result.\n");
    return;
  }

  EXPECT_LT(0, ret);
  EXPECT_EQ(1U, signaled);
#else  /* NO_PSTORE */
  GTEST_LOG_(INFO) << "This test does nothing because of NO_PSTORE.\n";
#endif /* NO_PSTORE */
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
#endif  // USING_LOGGER_DEFAULT

#ifdef USING_LOGGER_DEFAULT  // Do not retest ratelimit
TEST(liblog, __android_log_ratelimit) {
  time_t state = 0;

  errno = 42;
  // Prime
  __android_log_ratelimit(3, &state);
  EXPECT_EQ(errno, 42);
  // Check
  EXPECT_FALSE(__android_log_ratelimit(3, &state));
  sleep(1);
  EXPECT_FALSE(__android_log_ratelimit(3, &state));
  sleep(4);
  EXPECT_TRUE(__android_log_ratelimit(3, &state));
  sleep(5);
  EXPECT_TRUE(__android_log_ratelimit(3, &state));

  // API checks
  IF_ALOG_RATELIMIT_LOCAL(3, &state) {
    EXPECT_FALSE(0 != "IF_ALOG_RATELIMIT_LOCAL(3, &state)");
  }

  IF_ALOG_RATELIMIT() {
    ;
  }
  else {
    EXPECT_TRUE(0 == "IF_ALOG_RATELIMIT()");
  }
  IF_ALOG_RATELIMIT() {
    EXPECT_FALSE(0 != "IF_ALOG_RATELIMIT()");
  }
  // Do not test default seconds, to allow liblog to tune freely
}
#endif  // USING_LOGGER_DEFAULT

#ifdef USING_LOGGER_DEFAULT  // Do not retest event mapping functionality
TEST(liblog, android_lookupEventTagNum) {
#ifdef __ANDROID__
  EventTagMap* map = android_openEventTagMap(NULL);
  EXPECT_TRUE(NULL != map);
  std::string Name = android::base::StringPrintf("a%d", getpid());
  int tag = android_lookupEventTagNum(map, Name.c_str(), "(new|1)",
                                      ANDROID_LOG_UNKNOWN);
  android_closeEventTagMap(map);
  if (tag == -1) system("tail -3 /dev/event-log-tags >&2");
  EXPECT_NE(-1, tag);
  EXPECT_NE(0, tag);
  EXPECT_GT(UINT32_MAX, (unsigned)tag);
#else
  GTEST_LOG_(INFO) << "This test does nothing.\n";
#endif
}
#endif  // USING_LOGGER_DEFAULT
