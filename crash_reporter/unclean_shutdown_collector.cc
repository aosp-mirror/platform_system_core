/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "unclean_shutdown_collector.h"

#include <base/files/file_util.h>
#include <base/logging.h>

static const char kUncleanShutdownFile[] =
    "/var/lib/crash_reporter/pending_clean_shutdown";

// Files created by power manager used for crash reporting.
static const char kPowerdTracePath[] = "/var/lib/power_manager";
// Presence of this file indicates that the system was suspended
static const char kPowerdSuspended[] = "powerd_suspended";

using base::FilePath;

UncleanShutdownCollector::UncleanShutdownCollector()
    : unclean_shutdown_file_(kUncleanShutdownFile),
      powerd_trace_path_(kPowerdTracePath),
      powerd_suspended_file_(powerd_trace_path_.Append(kPowerdSuspended)) {
}

UncleanShutdownCollector::~UncleanShutdownCollector() {
}

bool UncleanShutdownCollector::Enable() {
  FilePath file_path(unclean_shutdown_file_);
  base::CreateDirectory(file_path.DirName());
  if (base::WriteFile(file_path, "", 0) != 0) {
    LOG(ERROR) << "Unable to create shutdown check file";
    return false;
  }
  return true;
}

bool UncleanShutdownCollector::DeleteUncleanShutdownFiles() {
  if (!base::DeleteFile(FilePath(unclean_shutdown_file_), false)) {
    LOG(ERROR) << "Failed to delete unclean shutdown file "
               << unclean_shutdown_file_;
    return false;
  }
  // Delete power manager state file if it exists.
  base::DeleteFile(powerd_suspended_file_, false);
  return true;
}

bool UncleanShutdownCollector::Collect() {
  FilePath unclean_file_path(unclean_shutdown_file_);
  if (!base::PathExists(unclean_file_path)) {
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

bool UncleanShutdownCollector::DeadBatteryCausedUncleanShutdown() {
  // Check for case of battery running out while suspended.
  if (base::PathExists(powerd_suspended_file_)) {
    LOG(INFO) << "Unclean shutdown occurred while suspended. Not counting "
              << "toward unclean shutdown statistic.";
    return true;
  }
  return false;
}
