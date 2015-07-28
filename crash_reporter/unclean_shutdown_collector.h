// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
#define CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"

// Unclean shutdown collector.
class UncleanShutdownCollector : public CrashCollector {
 public:
  UncleanShutdownCollector();
  ~UncleanShutdownCollector() override;

  // Enable collection - signal that a boot has started.
  bool Enable();

  // Collect if there is was an unclean shutdown. Returns true if
  // there was, false otherwise.
  bool Collect();

  // Disable collection - signal that the system has been shutdown cleanly.
  bool Disable();

 private:
  friend class UncleanShutdownCollectorTest;
  FRIEND_TEST(UncleanShutdownCollectorTest, EnableCannotWrite);
  FRIEND_TEST(UncleanShutdownCollectorTest, CollectDeadBatterySuspended);

  bool DeleteUncleanShutdownFiles();

  // Check for unclean shutdown due to battery running out by analyzing powerd
  // trace files.
  bool DeadBatteryCausedUncleanShutdown();

  const char *unclean_shutdown_file_;
  base::FilePath powerd_trace_path_;
  base::FilePath powerd_suspended_file_;

  DISALLOW_COPY_AND_ASSIGN(UncleanShutdownCollector);
};

#endif  // CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
