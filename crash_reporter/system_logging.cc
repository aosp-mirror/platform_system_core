// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdarg.h>
#include <syslog.h>

#include "crash-reporter/system_logging.h"

std::string SystemLoggingImpl::identity_;

SystemLoggingImpl::SystemLoggingImpl() {
}

SystemLoggingImpl::~SystemLoggingImpl() {
}

void SystemLoggingImpl::Initialize(const char *ident) {
  // Man page does not specify if openlog copies its string or assumes
  // the pointer is always valid, so make its scope global.
  identity_ = ident;
  openlog(identity_.c_str(), LOG_PID, LOG_USER);
}

void SystemLoggingImpl::LogInfo(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  vsyslog(LOG_INFO, format, vl);
  va_end(vl);
}

void SystemLoggingImpl::LogWarning(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  vsyslog(LOG_WARNING, format, vl);
  va_end(vl);
}

void SystemLoggingImpl::LogError(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  vsyslog(LOG_ERR, format, vl);
  va_end(vl);
}
