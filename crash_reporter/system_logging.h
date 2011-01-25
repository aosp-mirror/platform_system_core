// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_SYSTEM_LOGGING_H_
#define CRASH_REPORTER_SYSTEM_LOGGING_H_

#include <stdarg.h>
#include <string>

class SystemLogging {
 public:
  virtual void Initialize(const char *ident) = 0;
  virtual void LogInfo(const char *format, ...) = 0;
  virtual void LogWarning(const char *format, ...) = 0;
  virtual void LogError(const char *format, ...) = 0;
  virtual void set_accumulating(bool value) = 0;
  virtual std::string get_accumulator() = 0;
};

// SystemLoggingImpl implements SystemLogging but adds the
// capability of accumulating the log to a STL string.
class SystemLoggingImpl : public SystemLogging {
 public:
  SystemLoggingImpl();
  virtual ~SystemLoggingImpl();
  virtual void Initialize(const char *ident);
  virtual void LogInfo(const char *format, ...);
  virtual void LogWarning(const char *format, ...);
  virtual void LogError(const char *format, ...);
  virtual void set_accumulating(bool value) {
    is_accumulating_ = value;
  }
  virtual std::string get_accumulator() {
    return accumulator_;
  }
 private:
  static std::string identity_;
  std::string accumulator_;
  bool is_accumulating_;
  void LogWithLevel(int level, const char *format,
                    va_list arg_list);
};

#endif  // CRASH_REPORTER_SYSTEM_LOGGING_H_
