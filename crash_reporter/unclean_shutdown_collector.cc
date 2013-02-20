// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/unclean_shutdown_collector.h"

#include "base/file_util.h"
#include "base/logging.h"

static const char kUncleanShutdownFile[] =
    "/var/lib/crash_reporter/pending_clean_shutdown";

// Files created by power manager used for crash reporting.
static const char kPowerdTracePath[] = "/var/lib/power_manager";
// Presence of this file indicates that the system was suspended
static const char kPowerdSuspended[] = "powerd_suspended";
// Presence of this file indicates that the battery was critically low.
static const char kPowerdLowBattery[] = "powerd_low_battery";

using base::FilePath;

UncleanShutdownCollector::UncleanShutdownCollector()
    : unclean_shutdown_file_(kUncleanShutdownFile),
      powerd_trace_path_(kPowerdTracePath),
      powerd_suspended_file_(powerd_trace_path_.Append(kPowerdSuspended)),
      powerd_low_battery_file_(powerd_trace_path_.Append(kPowerdLowBattery)) {
}

UncleanShutdownCollector::~UncleanShutdownCollector() {
}

bool UncleanShutdownCollector::Enable() {
  FilePath file_path(unclean_shutdown_file_);
  file_util::CreateDirectory(file_path.DirName());
  if (file_util::WriteFile(file_path, "", 0) != 0) {
    LOG(ERROR) << "Unable to create shutdown check file";
    return false;
  }
  return true;
}

bool UncleanShutdownCollector::DeleteUncleanShutdownFiles() {
  if (!file_util::Delete(FilePath(unclean_shutdown_file_), false)) {
    LOG(ERROR) << "Failed to delete unclean shutdown file "
               << unclean_shutdown_file_;
    return false;
  }
  // Delete power manager trace files if they exist.
  file_util::Delete(powerd_suspended_file_, false);
  file_util::Delete(powerd_low_battery_file_, false);
  return true;
}

bool UncleanShutdownCollector::Collect() {
  FilePath unclean_file_path(unclean_shutdown_file_);
  if (!file_util::PathExists(unclean_file_path)) {
    return false;
  }
  LOG(WARNING) << "Last shutdown was not clean";
  if (DeadBatteryCausedUncleanShutdown()) {
    DeleteUncleanShutdownFiles();
    return false;
  }
  DeleteUncleanShutdownFiles();

  if (is_feedback_allowed_function_()) {
    count_crash_function_();
  }
  return true;
}

bool UncleanShutdownCollector::Disable() {
  LOG(INFO) << "Clean shutdown signalled";
  return DeleteUncleanShutdownFiles();
}

bool UncleanShutdownCollector::DeadBatteryCausedUncleanShutdown()
{
  // Check for case of battery running out while suspended.
  if (file_util::PathExists(powerd_suspended_file_)) {
    LOG(INFO) << "Unclean shutdown occurred while suspended. Not counting "
              << "toward unclean shutdown statistic.";
    return true;
  }
  // Check for case of battery running out after resuming from a low-battery
  // suspend.
  if (file_util::PathExists(powerd_low_battery_file_)) {
    LOG(INFO) << "Unclean shutdown occurred while running with battery "
              << "critically low.  Not counting toward unclean shutdown "
              << "statistic.";
    return true;
  }
  return false;
}
