// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdarg.h>

#include "base/string_util.h"
#include "crash-reporter/system_logging_mock.h"

void SystemLoggingMock::LogInfo(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  log_ += ident_ + "info: ";
  StringAppendV(&log_, format, vl);
  log_ += "\n";
  va_end(vl);
}

void SystemLoggingMock::LogWarning(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  log_ += ident_ + "warning: ";
  StringAppendV(&log_, format, vl);
  log_ += "\n";
  va_end(vl);
}

void SystemLoggingMock::LogError(const char *format, ...) {
  va_list vl;
  va_start(vl, format);
  log_ += ident_ + "error: ";
  StringAppendV(&log_, format, vl);
  log_ += "\n";
  va_end(vl);
}
