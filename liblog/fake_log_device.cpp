/*
 * Copyright (C) 2008-2014 The Android Open Source Project
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
/*
 * Intercepts log messages intended for the Android log device.
 * Messages are printed to stderr.
 */

#include "fake_log_device.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <mutex>

#include <android/log.h>
#include <log/log_id.h>
#include <log/logprint.h>

#include "log_portability.h"
#include "logger.h"

#define kMaxTagLen 16 /* from the long-dead utils/Log.cpp */

#define kTagSetSize 16 /* arbitrary */

#if 0
#define TRACE(...) printf("fake_log_device: " __VA_ARGS__)
#else
#define TRACE(...) ((void)0)
#endif

static int FakeAvailable(log_id_t);
static int FakeOpen();
static void FakeClose();
static int FakeWrite(log_id_t log_id, struct timespec* ts, struct iovec* vec, size_t nr);

struct android_log_transport_write fakeLoggerWrite = {
    .name = "fake",
    .logMask = 0,
    .available = FakeAvailable,
    .open = FakeOpen,
    .close = FakeClose,
    .write = FakeWrite,
};

typedef struct LogState {
  /* global minimum priority */
  int global_min_priority;

  /* output format */
  AndroidLogPrintFormat output_format;

  /* tags and priorities */
  struct {
    char tag[kMaxTagLen];
    int minPriority;
  } tagSet[kTagSetSize];
} LogState;

/*
 * Locking.  Since we're emulating a device, we need to be prepared
 * to have multiple callers at the same time.  This lock is used
 * to both protect the fd list and to prevent LogStates from being
 * freed out from under a user.
 */
std::mutex mutex;

static LogState log_state;

static int FakeAvailable(log_id_t) {
  return 0;
}

/*
 * Configure logging based on ANDROID_LOG_TAGS environment variable.  We
 * need to parse a string that looks like
 *
 *   *:v jdwp:d dalvikvm:d dalvikvm-gc:i dalvikvmi:i
 *
 * The tag (or '*' for the global level) comes first, followed by a colon
 * and a letter indicating the minimum priority level we're expected to log.
 * This can be used to reveal or conceal logs with specific tags.
 *
 * We also want to check ANDROID_PRINTF_LOG to determine how the output
 * will look.
 */
int FakeOpen() {
  std::lock_guard guard{mutex};

  /* global min priority defaults to "info" level */
  log_state.global_min_priority = ANDROID_LOG_INFO;

  /*
   * This is based on the the long-dead utils/Log.cpp code.
   */
  const char* tags = getenv("ANDROID_LOG_TAGS");
  TRACE("Found ANDROID_LOG_TAGS='%s'\n", tags);
  if (tags != NULL) {
    int entry = 0;

    while (*tags != '\0') {
      char tagName[kMaxTagLen];
      int i, minPrio;

      while (isspace(*tags)) tags++;

      i = 0;
      while (*tags != '\0' && !isspace(*tags) && *tags != ':' && i < kMaxTagLen) {
        tagName[i++] = *tags++;
      }
      if (i == kMaxTagLen) {
        TRACE("ERROR: env tag too long (%d chars max)\n", kMaxTagLen - 1);
        return 0;
      }
      tagName[i] = '\0';

      /* default priority, if there's no ":" part; also zero out '*' */
      minPrio = ANDROID_LOG_VERBOSE;
      if (tagName[0] == '*' && tagName[1] == '\0') {
        minPrio = ANDROID_LOG_DEBUG;
        tagName[0] = '\0';
      }

      if (*tags == ':') {
        tags++;
        if (*tags >= '0' && *tags <= '9') {
          if (*tags >= ('0' + ANDROID_LOG_SILENT))
            minPrio = ANDROID_LOG_VERBOSE;
          else
            minPrio = *tags - '\0';
        } else {
          switch (*tags) {
            case 'v':
              minPrio = ANDROID_LOG_VERBOSE;
              break;
            case 'd':
              minPrio = ANDROID_LOG_DEBUG;
              break;
            case 'i':
              minPrio = ANDROID_LOG_INFO;
              break;
            case 'w':
              minPrio = ANDROID_LOG_WARN;
              break;
            case 'e':
              minPrio = ANDROID_LOG_ERROR;
              break;
            case 'f':
              minPrio = ANDROID_LOG_FATAL;
              break;
            case 's':
              minPrio = ANDROID_LOG_SILENT;
              break;
            default:
              minPrio = ANDROID_LOG_DEFAULT;
              break;
          }
        }

        tags++;
        if (*tags != '\0' && !isspace(*tags)) {
          TRACE("ERROR: garbage in tag env; expected whitespace\n");
          TRACE("       env='%s'\n", tags);
          return 0;
        }
      }

      if (tagName[0] == 0) {
        log_state.global_min_priority = minPrio;
        TRACE("+++ global min prio %d\n", logState->globalMinPriority);
      } else {
        log_state.tagSet[entry].minPriority = minPrio;
        strcpy(log_state.tagSet[entry].tag, tagName);
        TRACE("+++ entry %d: %s:%d\n", entry, logState->tagSet[entry].tag,
              logState->tagSet[entry].minPriority);
        entry++;
      }
    }
  }

  /*
   * Taken from the long-dead utils/Log.cpp
   */
  const char* fstr = getenv("ANDROID_PRINTF_LOG");
  AndroidLogPrintFormat format;
  if (fstr == NULL) {
    format = FORMAT_BRIEF;
  } else {
    if (strcmp(fstr, "brief") == 0)
      format = FORMAT_BRIEF;
    else if (strcmp(fstr, "process") == 0)
      format = FORMAT_PROCESS;
    else if (strcmp(fstr, "tag") == 0)
      format = FORMAT_PROCESS;
    else if (strcmp(fstr, "thread") == 0)
      format = FORMAT_PROCESS;
    else if (strcmp(fstr, "raw") == 0)
      format = FORMAT_PROCESS;
    else if (strcmp(fstr, "time") == 0)
      format = FORMAT_PROCESS;
    else if (strcmp(fstr, "long") == 0)
      format = FORMAT_PROCESS;
    else
      format = (AndroidLogPrintFormat)atoi(fstr);  // really?!
  }

  log_state.output_format = format;
  return 0;
}

/*
 * Return a human-readable string for the priority level.  Always returns
 * a valid string.
 */
static const char* getPriorityString(int priority) {
  /* the first character of each string should be unique */
  static const char* priorityStrings[] = {"Verbose", "Debug", "Info", "Warn", "Error", "Assert"};
  int idx;

  idx = (int)priority - (int)ANDROID_LOG_VERBOSE;
  if (idx < 0 || idx >= (int)(sizeof(priorityStrings) / sizeof(priorityStrings[0])))
    return "?unknown?";
  return priorityStrings[idx];
}

#if defined(_WIN32)
/*
 * WIN32 does not have writev().
 * Make up something to replace it.
 */
static ssize_t fake_writev(int fd, const struct iovec* iov, int iovcnt) {
  ssize_t result = 0;
  const struct iovec* end = iov + iovcnt;
  for (; iov < end; iov++) {
    ssize_t w = write(fd, iov->iov_base, iov->iov_len);
    if (w != (ssize_t)iov->iov_len) {
      if (w < 0) return w;
      return result + w;
    }
    result += w;
  }
  return result;
}

#define writev fake_writev
#endif

/*
 * Write a filtered log message to stderr.
 *
 * Log format parsing taken from the long-dead utils/Log.cpp.
 */
static void ShowLog(int logPrio, const char* tag, const char* msg) {
#if !defined(_WIN32)
  struct tm tmBuf;
#endif
  struct tm* ptm;
  char timeBuf[32];
  char prefixBuf[128], suffixBuf[128];
  char priChar;
  time_t when;
#if !defined(_WIN32)
  pid_t pid, tid;
#else
  uint32_t pid, tid;
#endif

  TRACE("LOG %d: %s %s", logPrio, tag, msg);

  priChar = getPriorityString(logPrio)[0];
  when = time(NULL);
  pid = tid = getpid();  // find gettid()?

/*
 * Get the current date/time in pretty form
 *
 * It's often useful when examining a log with "less" to jump to
 * a specific point in the file by searching for the date/time stamp.
 * For this reason it's very annoying to have regexp meta characters
 * in the time stamp.  Don't use forward slashes, parenthesis,
 * brackets, asterisks, or other special chars here.
 */
#if !defined(_WIN32)
  ptm = localtime_r(&when, &tmBuf);
#else
  ptm = localtime(&when);
#endif
  // strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", ptm);
  strftime(timeBuf, sizeof(timeBuf), "%m-%d %H:%M:%S", ptm);

  /*
   * Construct a buffer containing the log header and log message.
   */
  size_t prefixLen, suffixLen;

  switch (log_state.output_format) {
    case FORMAT_TAG:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "%c/%-8s: ", priChar, tag);
      strcpy(suffixBuf, "\n");
      suffixLen = 1;
      break;
    case FORMAT_PROCESS:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "%c(%5d) ", priChar, pid);
      suffixLen = snprintf(suffixBuf, sizeof(suffixBuf), "  (%s)\n", tag);
      break;
    case FORMAT_THREAD:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "%c(%5d:%5d) ", priChar, pid, tid);
      strcpy(suffixBuf, "\n");
      suffixLen = 1;
      break;
    case FORMAT_RAW:
      prefixBuf[0] = 0;
      prefixLen = 0;
      strcpy(suffixBuf, "\n");
      suffixLen = 1;
      break;
    case FORMAT_TIME:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "%s %-8s\n\t", timeBuf, tag);
      strcpy(suffixBuf, "\n");
      suffixLen = 1;
      break;
    case FORMAT_THREADTIME:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "%s %5d %5d %c %-8s \n\t", timeBuf, pid,
                           tid, priChar, tag);
      strcpy(suffixBuf, "\n");
      suffixLen = 1;
      break;
    case FORMAT_LONG:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "[ %s %5d:%5d %c/%-8s ]\n", timeBuf, pid,
                           tid, priChar, tag);
      strcpy(suffixBuf, "\n\n");
      suffixLen = 2;
      break;
    default:
      prefixLen = snprintf(prefixBuf, sizeof(prefixBuf), "%c/%-8s(%5d): ", priChar, tag, pid);
      strcpy(suffixBuf, "\n");
      suffixLen = 1;
      break;
  }

  /*
   * Figure out how many lines there will be.
   */
  const char* end = msg + strlen(msg);
  size_t numLines = 0;
  const char* p = msg;
  while (p < end) {
    if (*p++ == '\n') numLines++;
  }
  if (p > msg && *(p - 1) != '\n') {
    numLines++;
  }

  /*
   * Create an array of iovecs large enough to write all of
   * the lines with a prefix and a suffix.
   */
  const size_t INLINE_VECS = 64;
  const size_t MAX_LINES = ((size_t)~0) / (3 * sizeof(struct iovec*));
  struct iovec stackVec[INLINE_VECS];
  struct iovec* vec = stackVec;
  size_t numVecs;

  if (numLines > MAX_LINES) numLines = MAX_LINES;

  numVecs = numLines * 3;  // 3 iovecs per line.
  if (numVecs > INLINE_VECS) {
    vec = (struct iovec*)malloc(sizeof(struct iovec) * numVecs);
    if (vec == NULL) {
      msg = "LOG: write failed, no memory";
      numVecs = INLINE_VECS;
      numLines = numVecs / 3;
      vec = stackVec;
    }
  }

  /*
   * Fill in the iovec pointers.
   */
  p = msg;
  struct iovec* v = vec;
  int totalLen = 0;
  while (numLines > 0 && p < end) {
    if (prefixLen > 0) {
      v->iov_base = prefixBuf;
      v->iov_len = prefixLen;
      totalLen += prefixLen;
      v++;
    }
    const char* start = p;
    while (p < end && *p != '\n') {
      p++;
    }
    if ((p - start) > 0) {
      v->iov_base = (void*)start;
      v->iov_len = p - start;
      totalLen += p - start;
      v++;
    }
    if (*p == '\n') p++;
    if (suffixLen > 0) {
      v->iov_base = suffixBuf;
      v->iov_len = suffixLen;
      totalLen += suffixLen;
      v++;
    }
    numLines -= 1;
  }

  /*
   * Write the entire message to the log file with a single writev() call.
   * We need to use this rather than a collection of printf()s on a FILE*
   * because of multi-threading and multi-process issues.
   *
   * If the file was not opened with O_APPEND, this will produce interleaved
   * output when called on the same file from multiple processes.
   *
   * If the file descriptor is actually a network socket, the writev()
   * call may return with a partial write.  Putting the writev() call in
   * a loop can result in interleaved data.  This can be alleviated
   * somewhat by wrapping the writev call in the Mutex.
   */

  for (;;) {
    int cc = writev(fileno(stderr), vec, v - vec);

    if (cc == totalLen) break;

    if (cc < 0) {
      if (errno == EINTR) continue;

      /* can't really log the failure; for now, throw out a stderr */
      fprintf(stderr, "+++ LOG: write failed (errno=%d)\n", errno);
      break;
    } else {
      /* shouldn't happen when writing to file or tty */
      fprintf(stderr, "+++ LOG: write partial (%d of %d)\n", cc, totalLen);
      break;
    }
  }

  /* if we allocated storage for the iovecs, free it */
  if (vec != stackVec) free(vec);
}

/*
 * Receive a log message.  We happen to know that "vector" has three parts:
 *
 *  priority (1 byte)
 *  tag (N bytes -- null-terminated ASCII string)
 *  message (N bytes -- null-terminated ASCII string)
 */
static int FakeWrite(log_id_t log_id, struct timespec*, struct iovec* vector, size_t count) {
  /* Make sure that no-one frees the LogState while we're using it.
   * Also guarantees that only one thread is in showLog() at a given
   * time (if it matters).
   */
  std::lock_guard guard{mutex};

  if (log_id == LOG_ID_EVENTS || log_id == LOG_ID_STATS || log_id == LOG_ID_SECURITY) {
    TRACE("%s: ignoring binary log\n", android_log_id_to_name(log_id));
    int len = 0;
    for (size_t i = 0; i < count; ++i) {
      len += vector[i].iov_len;
    }
    return len;
  }

  if (count != 3) {
    TRACE("%s: writevLog with count=%d not expected\n", android_log_id_to_name(log_id), count);
    return -1;
  }

  /* pull out the three fields */
  int logPrio = *(const char*)vector[0].iov_base;
  const char* tag = (const char*)vector[1].iov_base;
  const char* msg = (const char*)vector[2].iov_base;

  /* see if this log tag is configured */
  int minPrio = log_state.global_min_priority;
  for (size_t i = 0; i < kTagSetSize; i++) {
    if (log_state.tagSet[i].minPriority == ANDROID_LOG_UNKNOWN)
      break; /* reached end of configured values */

    if (strcmp(log_state.tagSet[i].tag, tag) == 0) {
      minPrio = log_state.tagSet[i].minPriority;
      break;
    }
  }

  if (logPrio >= minPrio) {
    ShowLog(logPrio, tag, msg);
  }

  int len = 0;
  for (size_t i = 0; i < count; ++i) {
    len += vector[i].iov_len;
  }
  return len;
}

/*
 * Reset out state.
 *
 * The logger API has no means or need to 'stop' or 'close' using the logs,
 * and as such, there is no way for that 'stop' or 'close' to translate into
 * a close operation to the fake log handler. fakeLogClose is provided for
 * completeness only.
 *
 * We have no intention of adding a log close operation as it would complicate
 * every user of the logging API with no gain since the only valid place to
 * call is in the exit handler. Logging can continue in the exit handler to
 * help debug HOST tools ...
 */
static void FakeClose() {
  std::lock_guard guard{mutex};

  memset(&log_state, 0, sizeof(log_state));
}

int __android_log_is_loggable(int prio, const char*, int def) {
  int logLevel = def;
  return logLevel >= 0 && prio >= logLevel;
}

int __android_log_is_loggable_len(int prio, const char*, size_t, int def) {
  int logLevel = def;
  return logLevel >= 0 && prio >= logLevel;
}

int __android_log_is_debuggable() {
  return 1;
}
