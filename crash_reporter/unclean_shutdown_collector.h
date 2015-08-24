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

#ifndef CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_
#define CRASH_REPORTER_UNCLEAN_SHUTDOWN_COLLECTOR_H_

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash_collector.h"

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
