// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/unclean_shutdown_collector.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "crash-reporter/system_logging.h"

static const char kUncleanShutdownFile[] =
    "/var/lib/crash_reporter/pending_clean_shutdown";

UncleanShutdownCollector::UncleanShutdownCollector()
    : unclean_shutdown_file_(kUncleanShutdownFile) {
}

UncleanShutdownCollector::~UncleanShutdownCollector() {
}

bool UncleanShutdownCollector::Enable() {
  FilePath file_path(unclean_shutdown_file_);
  file_util::CreateDirectory(file_path.DirName());
  if (file_util::WriteFile(file_path, "", 0) != 0) {
    logger_->LogError("Unable to create shutdown check file");
    return false;
  }
  return true;
}

bool UncleanShutdownCollector::DeleteUncleanShutdownFile() {
  if (!file_util::Delete(FilePath(unclean_shutdown_file_), false)) {
    logger_->LogError("Failed to delete unclean shutdown file %s",
                      unclean_shutdown_file_);
    return false;
  }
  return true;
}

bool UncleanShutdownCollector::Collect() {
  FilePath unclean_file_path(unclean_shutdown_file_);
  if (!file_util::PathExists(unclean_file_path)) {
    return false;
  }
  logger_->LogWarning("Last shutdown was not clean");
  DeleteUncleanShutdownFile();

  if (is_feedback_allowed_function_()) {
    count_crash_function_();
  }
  return true;
}

bool UncleanShutdownCollector::Disable() {
  logger_->LogInfo("Clean shutdown signalled");
  return DeleteUncleanShutdownFile();
}
