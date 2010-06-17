// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash/user_collector.h"
#include "metrics/metrics_library.h"

// This procfs file is used to cause kernel core file writing to
// instead pipe the core file into a user space process.  See
// core(5) man page.
static const char kCorePatternFile[] = "/proc/sys/kernel/core_pattern";

UserCollector::UserCollector()
    : core_pattern_file_(kCorePatternFile),
      count_crash_function_(NULL),
      initialized_(false),
      is_feedback_allowed_function_(NULL),
      logger_(NULL) {
}

void UserCollector::Initialize(
    UserCollector::CountCrashFunction count_crash_function,
    const std::string &our_path,
    UserCollector::IsFeedbackAllowedFunction is_feedback_allowed_function,
    SystemLogging *logger) {
  CHECK(count_crash_function != NULL);
  CHECK(is_feedback_allowed_function != NULL);
  CHECK(logger != NULL);

  count_crash_function_ = count_crash_function;
  our_path_ = our_path;
  is_feedback_allowed_function_ = is_feedback_allowed_function;
  logger_ = logger;
  initialized_ = true;
}

UserCollector::~UserCollector() {
}

std::string UserCollector::GetPattern(bool enabled) const {
  if (enabled) {
    return StringPrintf("|%s --signal=%%s --pid=%%p --exec=%%e",
                        our_path_.c_str());
  } else {
    return "core";
  }
}

bool UserCollector::SetUpInternal(bool enabled) {
  CHECK(initialized_);
  logger_->LogInfo("%s crash handling", enabled ? "Enabling" : "Disabling");
  std::string pattern = GetPattern(enabled);
  if (file_util::WriteFile(FilePath(core_pattern_file_),
                           pattern.c_str(),
                           pattern.length()) !=
      static_cast<int>(pattern.length())) {
    logger_->LogError("Unable to write %s", core_pattern_file_.c_str());
    return false;
  }
  return true;
}

void UserCollector::HandleCrash(int signal, int pid, const std::string &exec) {
  CHECK(initialized_);
  logger_->LogWarning("Received crash notification for %s[%d] sig %d",
                      exec.c_str(), pid, signal);

  if (is_feedback_allowed_function_()) {
    count_crash_function_();
  }
}
