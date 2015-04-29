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

#include "base/logging.h"

#include <libgen.h>

// For getprogname(3) or program_invocation_short_name.
#if defined(__ANDROID__) || defined(__APPLE__)
#include <stdlib.h>
#elif defined(__GLIBC__)
#include <errno.h>
#endif

#include <iostream>
#include <limits>
#include <mutex>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "base/strings.h"
#include "cutils/threads.h"

// Headers for LogMessage::LogLine.
#ifdef __ANDROID__
#include <android/set_abort_message.h>
#include "cutils/log.h"
#else
#include <sys/types.h>
#include <unistd.h>
#endif

namespace android {
namespace base {

static std::mutex logging_lock;

#ifdef __ANDROID__
static LogFunction gLogger = LogdLogger();
#else
static LogFunction gLogger = StderrLogger;
#endif

static bool gInitialized = false;
static LogSeverity gMinimumLogSeverity = INFO;
static std::unique_ptr<std::string> gProgramInvocationName;

#if defined(__GLIBC__)
static const char* getprogname() {
  return program_invocation_short_name;
}
#endif

static const char* ProgramInvocationName() {
  if (gProgramInvocationName == nullptr) {
    gProgramInvocationName.reset(new std::string(getprogname()));
  }

  return gProgramInvocationName->c_str();
}

void StderrLogger(LogId, LogSeverity severity, const char*, const char* file,
                  unsigned int line, const char* message) {
  static const char* log_characters = "VDIWEF";
  CHECK_EQ(strlen(log_characters), FATAL + 1U);
  char severity_char = log_characters[severity];
  fprintf(stderr, "%s %c %5d %5d %s:%u] %s\n", ProgramInvocationName(),
          severity_char, getpid(), gettid(), file, line, message);
}


#ifdef __ANDROID__
LogdLogger::LogdLogger(LogId default_log_id) : default_log_id_(default_log_id) {
}

static const android_LogPriority kLogSeverityToAndroidLogPriority[] = {
    ANDROID_LOG_VERBOSE, ANDROID_LOG_DEBUG, ANDROID_LOG_INFO,
    ANDROID_LOG_WARN,    ANDROID_LOG_ERROR, ANDROID_LOG_FATAL,
};
static_assert(arraysize(kLogSeverityToAndroidLogPriority) == FATAL + 1,
              "Mismatch in size of kLogSeverityToAndroidLogPriority and values "
              "in LogSeverity");

static const log_id kLogIdToAndroidLogId[] = {
    LOG_ID_MAX, LOG_ID_MAIN, LOG_ID_SYSTEM,
};
static_assert(arraysize(kLogIdToAndroidLogId) == SYSTEM + 1,
              "Mismatch in size of kLogIdToAndroidLogId and values in LogId");

void LogdLogger::operator()(LogId id, LogSeverity severity, const char* tag,
                            const char* file, unsigned int line,
                            const char* message) {
  int priority = kLogSeverityToAndroidLogPriority[severity];
  if (id == DEFAULT) {
    id = default_log_id_;
  }

  log_id lg_id = kLogIdToAndroidLogId[id];

  if (priority == ANDROID_LOG_FATAL) {
    __android_log_buf_print(lg_id, priority, tag, "%s:%u] %s", file, line,
                            message);
  } else {
    __android_log_buf_print(lg_id, priority, tag, "%s", message);
  }
}
#endif

void InitLogging(char* argv[], LogFunction&& logger) {
  SetLogger(std::forward<LogFunction>(logger));
  InitLogging(argv);
}

void InitLogging(char* argv[]) {
  if (gInitialized) {
    return;
  }

  gInitialized = true;

  // Stash the command line for later use. We can use /proc/self/cmdline on
  // Linux to recover this, but we don't have that luxury on the Mac, and there
  // are a couple of argv[0] variants that are commonly used.
  if (argv != nullptr) {
    gProgramInvocationName.reset(new std::string(basename(argv[0])));
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
          gMinimumLogSeverity = VERBOSE;
          continue;
        case 'd':
          gMinimumLogSeverity = DEBUG;
          continue;
        case 'i':
          gMinimumLogSeverity = INFO;
          continue;
        case 'w':
          gMinimumLogSeverity = WARNING;
          continue;
        case 'e':
          gMinimumLogSeverity = ERROR;
          continue;
        case 'f':
          gMinimumLogSeverity = FATAL;
          continue;
        // liblog will even suppress FATAL if you say 's' for silent, but that's
        // crazy!
        case 's':
          gMinimumLogSeverity = FATAL;
          continue;
      }
    }
    LOG(FATAL) << "unsupported '" << spec << "' in ANDROID_LOG_TAGS (" << tags
               << ")";
  }
}

void SetLogger(LogFunction&& logger) {
  std::lock_guard<std::mutex> lock(logging_lock);
  gLogger = std::move(logger);
}

// This indirection greatly reduces the stack impact of having lots of
// checks/logging in a function.
class LogMessageData {
 public:
  LogMessageData(const char* file, unsigned int line, LogId id,
                 LogSeverity severity, int error)
      : file_(file),
        line_number_(line),
        id_(id),
        severity_(severity),
        error_(error) {
    const char* last_slash = strrchr(file, '/');
    file = (last_slash == nullptr) ? file : last_slash + 1;
  }

  const char* GetFile() const {
    return file_;
  }

  unsigned int GetLineNumber() const {
    return line_number_;
  }

  LogSeverity GetSeverity() const {
    return severity_;
  }

  LogId GetId() const {
    return id_;
  }

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
  const LogId id_;
  const LogSeverity severity_;
  const int error_;

  DISALLOW_COPY_AND_ASSIGN(LogMessageData);
};

LogMessage::LogMessage(const char* file, unsigned int line, LogId id,
                       LogSeverity severity, int error)
    : data_(new LogMessageData(file, line, id, severity, error)) {
}

LogMessage::~LogMessage() {
  if (data_->GetSeverity() < gMinimumLogSeverity) {
    return;  // No need to format something we're not going to output.
  }

  // Finish constructing the message.
  if (data_->GetError() != -1) {
    data_->GetBuffer() << ": " << strerror(data_->GetError());
  }
  std::string msg(data_->ToString());

  if (msg.find('\n') == std::string::npos) {
    LogLine(data_->GetFile(), data_->GetLineNumber(), data_->GetId(),
            data_->GetSeverity(), msg.c_str());
  } else {
    msg += '\n';
    size_t i = 0;
    while (i < msg.size()) {
      size_t nl = msg.find('\n', i);
      msg[nl] = '\0';
      LogLine(data_->GetFile(), data_->GetLineNumber(), data_->GetId(),
              data_->GetSeverity(), &msg[i]);
      i = nl + 1;
    }
  }

  // Abort if necessary.
  if (data_->GetSeverity() == FATAL) {
#ifdef __ANDROID__
    android_set_abort_message(msg.c_str());
#endif
    abort();
  }
}

std::ostream& LogMessage::stream() {
  return data_->GetBuffer();
}

void LogMessage::LogLine(const char* file, unsigned int line, LogId id,
                         LogSeverity severity, const char* message) {
  const char* tag = ProgramInvocationName();
  std::lock_guard<std::mutex> lock(logging_lock);
  gLogger(id, severity, tag, file, line, message);
}

ScopedLogSeverity::ScopedLogSeverity(LogSeverity level) {
  old_ = gMinimumLogSeverity;
  gMinimumLogSeverity = level;
}

ScopedLogSeverity::~ScopedLogSeverity() {
  gMinimumLogSeverity = old_;
}

}  // namespace base
}  // namespace android
