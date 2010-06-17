// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_SYSTEM_LOGGING_H_
#define CRASH_SYSTEM_LOGGING_H_

#include <string>

class SystemLogging {
 public:
  virtual void Initialize(const char *ident) = 0;
  virtual void LogInfo(const char *format, ...) = 0;
  virtual void LogWarning(const char *format, ...) = 0;
  virtual void LogError(const char *format, ...) = 0;
};

class SystemLoggingImpl : public SystemLogging {
 public:
  SystemLoggingImpl();
  virtual ~SystemLoggingImpl();
  virtual void Initialize(const char *ident);
  virtual void LogInfo(const char *format, ...);
  virtual void LogWarning(const char *format, ...);
  virtual void LogError(const char *format, ...);
 private:
  static std::string identity_;
};

#endif  // CRASH_SYSTEM_LOGGING_H_
