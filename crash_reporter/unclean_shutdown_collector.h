// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
#define _CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_

#include <string>

#include "base/file_path.h"
#include "crash-reporter/crash_collector.h"
#include "gtest/gtest_prod.h"  // for FRIEND_TEST

// Unclean shutdown collector.
class UncleanShutdownCollector : public CrashCollector {
 public:
  UncleanShutdownCollector();
  virtual ~UncleanShutdownCollector();

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
  FRIEND_TEST(UncleanShutdownCollectorTest, CollectDeadBatteryRunningLow);
  FRIEND_TEST(UncleanShutdownCollectorTest, CollectDeadBatterySuspended);

  bool DeleteUncleanShutdownFiles();

  // Check for unclean shutdown due to battery running out by analyzing powerd
  // trace files.
  bool DeadBatteryCausedUncleanShutdown();

  const char *unclean_shutdown_file_;
  base::FilePath powerd_trace_path_;
  base::FilePath powerd_suspended_file_;
  base::FilePath powerd_low_battery_file_;
};

#endif  // _CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
