// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/system_logging.h"

#include <syslog.h>

#include "base/stringprintf.h"

std::string SystemLoggingImpl::identity_;

SystemLoggingImpl::SystemLoggingImpl() : is_accumulating_(false) {
}

SystemLoggingImpl::~SystemLoggingImpl() {
}

void SystemLoggingImpl::Initialize(const char *ident) {
  // Man page does not specify if openlog copies its string or assumes
  // the pointer is always valid, so make its scope global.
  identity_ = ident;
  openlog(identity_.c_str(), LOG_PID, LOG_USER);
}

void SystemLoggingImpl::LogWithLevel(int level, const char *format,
                                     va_list arg_list) {
  std::string message = StringPrintV(format, arg_list);
  syslog(level, "%s", message.c_str());
  if (is_accumulating_) {
    accumulator_.append(message);
    accumulator_.push_back('\n');
  }
}

void SystemLoggingImpl::LogInfo(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  LogWithLevel(LOG_INFO, format, vl);
  va_end(vl);
}

void SystemLoggingImpl::LogWarning(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  LogWithLevel(LOG_WARNING, format, vl);
  va_end(vl);
}

void SystemLoggingImpl::LogError(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  LogWithLevel(LOG_ERR, format, vl);
  va_end(vl);
}
