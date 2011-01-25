// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_SYSTEM_LOGGING_MOCK_H_
#define CRASH_REPORTER_SYSTEM_LOGGING_MOCK_H_

#include <string>

#include "crash-reporter/system_logging.h"

class SystemLoggingMock : public SystemLogging {
 public:
  void Initialize(const char *ident) {}
  virtual void LogInfo(const char *format, ...);
  virtual void LogWarning(const char *format, ...);
  virtual void LogError(const char *format, ...);
  virtual void set_accumulating(bool value);
  virtual std::string get_accumulator();

  const std::string &log() { return log_; }

  void clear() { log_.clear(); }

 private:
  static std::string identity_;
  std::string log_;
  std::string ident_;
};

#endif  // CRASH_REPORTER_SYSTEM_LOGGING_H_
