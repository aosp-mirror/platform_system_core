// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_USER_COLLECTOR_H_
#define _CRASH_USER_COLLECTOR_H_

#include <string>

#include "crash/system_logging.h"

class FilePath;

// User crash collector.
class UserCollector {
 public:
  typedef void (*CountCrashFunction)();
  typedef bool (*IsFeedbackAllowedFunction)();

  UserCollector();

  // Initialize the user crash collector for detection of crashes,
  // given a crash counting function, the path to this executable,
  // metrics collection enabled oracle, and system logger facility.
  // Crash detection/reporting is not enabled until Enable is
  // called.
  void Initialize(CountCrashFunction count_crash,
                  const std::string &our_path,
                  IsFeedbackAllowedFunction is_metrics_allowed,
                  SystemLogging *logger);

  virtual ~UserCollector();

  // Enable collection.
  bool Enable() { return SetUpInternal(true); }

  // Disable collection.
  bool Disable() { return SetUpInternal(false); }

  // Handle a specific user crash.
  void HandleCrash(int signal, int pid, const std::string &exec);

  // Set (override the default) core file pattern.
  void set_core_pattern_file(const std::string &pattern) {
    core_pattern_file_ = pattern;
  }

 private:
  friend class UserCollectorTest;

  std::string GetPattern(bool enabled) const;
  bool SetUpInternal(bool enabled);

  std::string core_pattern_file_;
  CountCrashFunction count_crash_function_;
  std::string our_path_;
  bool initialized_;
  IsFeedbackAllowedFunction is_feedback_allowed_function_;
  SystemLogging *logger_;
};

#endif  // _CRASH_USER_COLLECTOR_H_
