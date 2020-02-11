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

#if defined(_WIN32)
#include <windows.h>
#endif

#include "android-base/logging.h"

#include <fcntl.h>
#include <inttypes.h>
#include <libgen.h>
#include <time.h>

// For getprogname(3) or program_invocation_short_name.
#if defined(__ANDROID__) || defined(__APPLE__)
#include <stdlib.h>
#elif defined(__GLIBC__)
#include <errno.h>
#endif

#if defined(__linux__)
#include <sys/uio.h>
#endif

#include <atomic>
#include <iostream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include <android/log.h>
#ifdef __ANDROID__
#include <android/set_abort_message.h>
#else
#include <sys/types.h>
#include <unistd.h>
#endif

#include <android-base/file.h>
#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/strings.h>
#include <android-base/threads.h>

#include "liblog_symbols.h"

namespace android {
namespace base {

// BSD-based systems like Android/macOS have getprogname(). Others need us to provide one.
#if defined(__GLIBC__) || defined(_WIN32)
static const char* getprogname() {
#if defined(__GLIBC__)
  return program_invocation_short_name;
#elif defined(_WIN32)
  static bool first = true;
  static char progname[MAX_PATH] = {};

  if (first) {
    snprintf(progname, sizeof(progname), "%s",
             android::base::Basename(android::base::GetExecutablePath()).c_str());
    first = false;
  }

  return progname;
#endif
}
#endif

static const char* GetFileBasename(const char* file) {
  // We can't use basename(3) even on Unix because the Mac doesn't
  // have a non-modifying basename.
  const char* last_slash = strrchr(file, '/');
  if (last_slash != nullptr) {
    return last_slash + 1;
  }
#if defined(_WIN32)
  const char* last_backslash = strrchr(file, '\\');
  if (last_backslash != nullptr) {
    return last_backslash + 1;
  }
#endif
  return file;
}

#if defined(__linux__)
static int OpenKmsg() {
#if defined(__ANDROID__)
  // pick up 'file w /dev/kmsg' environment from daemon's init rc file
  const auto val = getenv("ANDROID_FILE__dev_kmsg");
  if (val != nullptr) {
    int fd;
    if (android::base::ParseInt(val, &fd, 0)) {
      auto flags = fcntl(fd, F_GETFL);
      if ((flags != -1) && ((flags & O_ACCMODE) == O_WRONLY)) return fd;
    }
  }
#endif
  return TEMP_FAILURE_RETRY(open("/dev/kmsg", O_WRONLY | O_CLOEXEC));
}
#endif

static LogId log_id_tToLogId(int buffer_id) {
  switch (buffer_id) {
    case LOG_ID_MAIN:
      return MAIN;
    case LOG_ID_SYSTEM:
      return SYSTEM;
    case LOG_ID_RADIO:
      return RADIO;
    case LOG_ID_CRASH:
      return CRASH;
    case LOG_ID_DEFAULT:
    default:
      return DEFAULT;
  }
}

static int LogIdTolog_id_t(LogId log_id) {
  switch (log_id) {
    case MAIN:
      return LOG_ID_MAIN;
    case SYSTEM:
      return LOG_ID_SYSTEM;
    case RADIO:
      return LOG_ID_RADIO;
    case CRASH:
      return LOG_ID_CRASH;
    case DEFAULT:
    default:
      return LOG_ID_DEFAULT;
  }
}

static LogSeverity PriorityToLogSeverity(int priority) {
  switch (priority) {
    case ANDROID_LOG_DEFAULT:
      return INFO;
    case ANDROID_LOG_VERBOSE:
      return VERBOSE;
    case ANDROID_LOG_DEBUG:
      return DEBUG;
    case ANDROID_LOG_INFO:
      return INFO;
    case ANDROID_LOG_WARN:
      return WARNING;
    case ANDROID_LOG_ERROR:
      return ERROR;
    case ANDROID_LOG_FATAL:
      return FATAL;
    default:
      return FATAL;
  }
}

static android_LogPriority LogSeverityToPriority(LogSeverity severity) {
  switch (severity) {
    case VERBOSE:
      return ANDROID_LOG_VERBOSE;
    case DEBUG:
      return ANDROID_LOG_DEBUG;
    case INFO:
      return ANDROID_LOG_INFO;
    case WARNING:
      return ANDROID_LOG_WARN;
    case ERROR:
      return ANDROID_LOG_ERROR;
    case FATAL_WITHOUT_ABORT:
    case FATAL:
    default:
      return ANDROID_LOG_FATAL;
  }
}

static std::mutex& LoggingLock() {
  static auto& logging_lock = *new std::mutex();
  return logging_lock;
}

// Only used for Q fallback.
static LogFunction& Logger() {
#ifdef __ANDROID__
  static auto& logger = *new LogFunction(LogdLogger());
#else
  static auto& logger = *new LogFunction(StderrLogger);
#endif
  return logger;
}

// Only used for Q fallback.
static AbortFunction& Aborter() {
  static auto& aborter = *new AbortFunction(DefaultAborter);
  return aborter;
}

// Only used for Q fallback.
static std::recursive_mutex& TagLock() {
  static auto& tag_lock = *new std::recursive_mutex();
  return tag_lock;
}
// Only used for Q fallback.
static std::string* gDefaultTag;

void SetDefaultTag(const std::string& tag) {
  static auto& liblog_functions = GetLibLogFunctions();
  if (liblog_functions) {
    liblog_functions->__android_log_set_default_tag(tag.c_str());
  } else {
    std::lock_guard<std::recursive_mutex> lock(TagLock());
    if (gDefaultTag != nullptr) {
      delete gDefaultTag;
      gDefaultTag = nullptr;
    }
    if (!tag.empty()) {
      gDefaultTag = new std::string(tag);
    }
  }
}

static bool gInitialized = false;

// Only used for Q fallback.
static LogSeverity gMinimumLogSeverity = INFO;

#if defined(__linux__)
void KernelLogger(android::base::LogId, android::base::LogSeverity severity,
                  const char* tag, const char*, unsigned int, const char* msg) {
  // clang-format off
  static constexpr int kLogSeverityToKernelLogLevel[] = {
      [android::base::VERBOSE] = 7,              // KERN_DEBUG (there is no verbose kernel log
                                                 //             level)
      [android::base::DEBUG] = 7,                // KERN_DEBUG
      [android::base::INFO] = 6,                 // KERN_INFO
      [android::base::WARNING] = 4,              // KERN_WARNING
      [android::base::ERROR] = 3,                // KERN_ERROR
      [android::base::FATAL_WITHOUT_ABORT] = 2,  // KERN_CRIT
      [android::base::FATAL] = 2,                // KERN_CRIT
  };
  // clang-format on
  static_assert(arraysize(kLogSeverityToKernelLogLevel) == android::base::FATAL + 1,
                "Mismatch in size of kLogSeverityToKernelLogLevel and values in LogSeverity");

  static int klog_fd = OpenKmsg();
  if (klog_fd == -1) return;

  int level = kLogSeverityToKernelLogLevel[severity];

  // The kernel's printk buffer is only 1024 bytes.
  // TODO: should we automatically break up long lines into multiple lines?
  // Or we could log but with something like "..." at the end?
  char buf[1024];
  size_t size = snprintf(buf, sizeof(buf), "<%d>%s: %s\n", level, tag, msg);
  if (size > sizeof(buf)) {
    size = snprintf(buf, sizeof(buf), "<%d>%s: %zu-byte message too long for printk\n",
                    level, tag, size);
  }

  iovec iov[1];
  iov[0].iov_base = buf;
  iov[0].iov_len = size;
  TEMP_FAILURE_RETRY(writev(klog_fd, iov, 1));
}
#endif

void StderrLogger(LogId, LogSeverity severity, const char* tag, const char* file, unsigned int line,
                  const char* message) {
  struct tm now;
  time_t t = time(nullptr);

#if defined(_WIN32)
  localtime_s(&now, &t);
#else
  localtime_r(&t, &now);
#endif

  char timestamp[32];
  strftime(timestamp, sizeof(timestamp), "%m-%d %H:%M:%S", &now);

  static const char log_characters[] = "VDIWEFF";
  static_assert(arraysize(log_characters) - 1 == FATAL + 1,
                "Mismatch in size of log_characters and values in LogSeverity");
  char severity_char = log_characters[severity];
  if (file != nullptr) {
    fprintf(stderr, "%s %c %s %5d %5" PRIu64 " %s:%u] %s\n", tag ? tag : "nullptr", severity_char,
            timestamp, getpid(), GetThreadId(), file, line, message);
  } else {
    fprintf(stderr, "%s %c %s %5d %5" PRIu64 " %s\n", tag ? tag : "nullptr", severity_char,
            timestamp, getpid(), GetThreadId(), message);
  }
}

void StdioLogger(LogId, LogSeverity severity, const char* /*tag*/, const char* /*file*/,
                 unsigned int /*line*/, const char* message) {
  if (severity >= WARNING) {
    fflush(stdout);
    fprintf(stderr, "%s: %s\n", GetFileBasename(getprogname()), message);
  } else {
    fprintf(stdout, "%s\n", message);
  }
}

void DefaultAborter(const char* abort_message) {
#ifdef __ANDROID__
  android_set_abort_message(abort_message);
#else
  UNUSED(abort_message);
#endif
  abort();
}


LogdLogger::LogdLogger(LogId default_log_id) : default_log_id_(default_log_id) {
}

void LogdLogger::operator()(LogId id, LogSeverity severity, const char* tag,
                            const char* file, unsigned int line,
                            const char* message) {
  android_LogPriority priority = LogSeverityToPriority(severity);
  if (id == DEFAULT) {
    id = default_log_id_;
  }

  int lg_id = LogIdTolog_id_t(id);

  char log_message_with_file[4068];  // LOGGER_ENTRY_MAX_PAYLOAD, not available in the NDK.
  if (priority == ANDROID_LOG_FATAL && file != nullptr) {
    snprintf(log_message_with_file, sizeof(log_message_with_file), "%s:%u] %s", file, line,
             message);
    message = log_message_with_file;
  }

  static auto& liblog_functions = GetLibLogFunctions();
  if (liblog_functions) {
    __android_logger_data logger_data = {sizeof(__android_logger_data),     lg_id, priority, tag,
                                         static_cast<const char*>(nullptr), 0};
    liblog_functions->__android_log_logd_logger(&logger_data, message);
  } else {
    __android_log_buf_print(lg_id, priority, tag, "%s", message);
  }
}

void InitLogging(char* argv[], LogFunction&& logger, AbortFunction&& aborter) {
  SetLogger(std::forward<LogFunction>(logger));
  SetAborter(std::forward<AbortFunction>(aborter));

  if (gInitialized) {
    return;
  }

  gInitialized = true;

  // Stash the command line for later use. We can use /proc/self/cmdline on
  // Linux to recover this, but we don't have that luxury on the Mac/Windows,
  // and there are a couple of argv[0] variants that are commonly used.
  if (argv != nullptr) {
    SetDefaultTag(basename(argv[0]));
  }

  const char* tags = getenv("ANDROID_LOG_TAGS");
  if (tags == nullptr) {
    return;
  }

  std::vector<std::string> specs = Split(tags, " ");
  for (size_t i = 0; i < specs.size(); ++i) {
    // "tag-pattern:[vdiwefs]"
    std::string spec(specs[i]);
    if (spec.size() == 3 && StartsWith(spec, "*:")) {
      switch (spec[2]) {
        case 'v':
          SetMinimumLogSeverity(VERBOSE);
          continue;
        case 'd':
          SetMinimumLogSeverity(DEBUG);
          continue;
        case 'i':
          SetMinimumLogSeverity(INFO);
          continue;
        case 'w':
          SetMinimumLogSeverity(WARNING);
          continue;
        case 'e':
          SetMinimumLogSeverity(ERROR);
          continue;
        case 'f':
          SetMinimumLogSeverity(FATAL_WITHOUT_ABORT);
          continue;
        // liblog will even suppress FATAL if you say 's' for silent, but that's
        // crazy!
        case 's':
          SetMinimumLogSeverity(FATAL_WITHOUT_ABORT);
          continue;
      }
    }
    LOG(FATAL) << "unsupported '" << spec << "' in ANDROID_LOG_TAGS (" << tags
               << ")";
  }
}

void SetLogger(LogFunction&& logger) {
  static auto& liblog_functions = GetLibLogFunctions();
  if (liblog_functions) {
    // We need to atomically swap the old and new pointers since other threads may be logging.
    // We know all threads will be using the new logger after __android_log_set_logger() returns,
    // so we can delete it then.
    // This leaks one std::function<> per instance of libbase if multiple copies of libbase within a
    // single process call SetLogger().  That is the same cost as having a static
    // std::function<>, which is the not-thread-safe alternative.
    static std::atomic<LogFunction*> logger_function(nullptr);
    auto* old_logger_function = logger_function.exchange(new LogFunction(logger));
    liblog_functions->__android_log_set_logger([](const struct __android_logger_data* logger_data,
                                                  const char* message) {
      auto log_id = log_id_tToLogId(logger_data->buffer_id);
      auto severity = PriorityToLogSeverity(logger_data->priority);

      auto& function = *logger_function.load(std::memory_order_acquire);
      function(log_id, severity, logger_data->tag, logger_data->file, logger_data->line, message);
    });
    delete old_logger_function;
  } else {
    std::lock_guard<std::mutex> lock(LoggingLock());
    Logger() = std::move(logger);
  }
}

void SetAborter(AbortFunction&& aborter) {
  static auto& liblog_functions = GetLibLogFunctions();
  if (liblog_functions) {
    // See the comment in SetLogger().
    static std::atomic<AbortFunction*> abort_function(nullptr);
    auto* old_abort_function = abort_function.exchange(new AbortFunction(aborter));
    __android_log_set_aborter([](const char* abort_message) {
      auto& function = *abort_function.load(std::memory_order_acquire);
      function(abort_message);
    });
    delete old_abort_function;
  } else {
    std::lock_guard<std::mutex> lock(LoggingLock());
    Aborter() = std::move(aborter);
  }
}

// This indirection greatly reduces the stack impact of having lots of
// checks/logging in a function.
class LogMessageData {
 public:
  LogMessageData(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                 int error)
      : file_(GetFileBasename(file)),
        line_number_(line),
        severity_(severity),
        tag_(tag),
        error_(error) {}

  const char* GetFile() const {
    return file_;
  }

  unsigned int GetLineNumber() const {
    return line_number_;
  }

  LogSeverity GetSeverity() const {
    return severity_;
  }

  const char* GetTag() const { return tag_; }

  int GetError() const {
    return error_;
  }

  std::ostream& GetBuffer() {
    return buffer_;
  }

  std::string ToString() const {
    return buffer_.str();
  }

 private:
  std::ostringstream buffer_;
  const char* const file_;
  const unsigned int line_number_;
  const LogSeverity severity_;
  const char* const tag_;
  const int error_;

  DISALLOW_COPY_AND_ASSIGN(LogMessageData);
};

LogMessage::LogMessage(const char* file, unsigned int line, LogId, LogSeverity severity,
                       const char* tag, int error)
    : LogMessage(file, line, severity, tag, error) {}

LogMessage::LogMessage(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                       int error)
    : data_(new LogMessageData(file, line, severity, tag, error)) {}

LogMessage::~LogMessage() {
  // Check severity again. This is duplicate work wrt/ LOG macros, but not LOG_STREAM.
  if (!WOULD_LOG(data_->GetSeverity())) {
    return;
  }

  // Finish constructing the message.
  if (data_->GetError() != -1) {
    data_->GetBuffer() << ": " << strerror(data_->GetError());
  }
  std::string msg(data_->ToString());

  if (data_->GetSeverity() == FATAL) {
#ifdef __ANDROID__
    // Set the bionic abort message early to avoid liblog doing it
    // with the individual lines, so that we get the whole message.
    android_set_abort_message(msg.c_str());
#endif
  }

  {
    // Do the actual logging with the lock held.
    std::lock_guard<std::mutex> lock(LoggingLock());
    if (msg.find('\n') == std::string::npos) {
      LogLine(data_->GetFile(), data_->GetLineNumber(), data_->GetSeverity(), data_->GetTag(),
              msg.c_str());
    } else {
      msg += '\n';
      size_t i = 0;
      while (i < msg.size()) {
        size_t nl = msg.find('\n', i);
        msg[nl] = '\0';
        LogLine(data_->GetFile(), data_->GetLineNumber(), data_->GetSeverity(), data_->GetTag(),
                &msg[i]);
        // Undo the zero-termination so we can give the complete message to the aborter.
        msg[nl] = '\n';
        i = nl + 1;
      }
    }
  }

  // Abort if necessary.
  if (data_->GetSeverity() == FATAL) {
    static auto& liblog_functions = GetLibLogFunctions();
    if (liblog_functions) {
      liblog_functions->__android_log_call_aborter(msg.c_str());
    } else {
      Aborter()(msg.c_str());
    }
  }
}

std::ostream& LogMessage::stream() {
  return data_->GetBuffer();
}

void LogMessage::LogLine(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                         const char* message) {
  static auto& liblog_functions = GetLibLogFunctions();
  auto priority = LogSeverityToPriority(severity);
  if (liblog_functions) {
    __android_logger_data logger_data = {
        sizeof(__android_logger_data), LOG_ID_DEFAULT, priority, tag, file, line};
    __android_log_write_logger_data(&logger_data, message);
  } else {
    if (tag == nullptr) {
      std::lock_guard<std::recursive_mutex> lock(TagLock());
      if (gDefaultTag == nullptr) {
        gDefaultTag = new std::string(getprogname());
      }

      Logger()(DEFAULT, severity, gDefaultTag->c_str(), file, line, message);
    } else {
      Logger()(DEFAULT, severity, tag, file, line, message);
    }
  }
}

LogSeverity GetMinimumLogSeverity() {
  static auto& liblog_functions = GetLibLogFunctions();
  if (liblog_functions) {
    return PriorityToLogSeverity(liblog_functions->__android_log_get_minimum_priority());
  } else {
    return gMinimumLogSeverity;
  }
}

bool ShouldLog(LogSeverity severity, const char* tag) {
  static auto& liblog_functions = GetLibLogFunctions();
  // Even though we're not using the R liblog functions in this function, if we're running on Q,
  // we need to fall back to using gMinimumLogSeverity, since __android_log_is_loggable() will not
  // take into consideration the value from SetMinimumLogSeverity().
  if (liblog_functions) {
    int priority = LogSeverityToPriority(severity);
    return __android_log_is_loggable(priority, tag, ANDROID_LOG_INFO);
  } else {
    return severity >= gMinimumLogSeverity;
  }
}

LogSeverity SetMinimumLogSeverity(LogSeverity new_severity) {
  static auto& liblog_functions = GetLibLogFunctions();
  if (liblog_functions) {
    auto priority = LogSeverityToPriority(new_severity);
    return PriorityToLogSeverity(liblog_functions->__android_log_set_minimum_priority(priority));
  } else {
    LogSeverity old_severity = gMinimumLogSeverity;
    gMinimumLogSeverity = new_severity;
    return old_severity;
  }
}

ScopedLogSeverity::ScopedLogSeverity(LogSeverity new_severity) {
  old_ = SetMinimumLogSeverity(new_severity);
}

ScopedLogSeverity::~ScopedLogSeverity() {
  SetMinimumLogSeverity(old_);
}

}  // namespace base
}  // namespace android
