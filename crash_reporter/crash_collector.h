// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_CRASH_COLLECTOR_H_
#define _CRASH_REPORTER_CRASH_COLLECTOR_H_

#include <string>
#include <sys/stat.h>

#include "gtest/gtest_prod.h"  // for FRIEND_TEST

class FilePath;
class SystemLogging;

// User crash collector.
class CrashCollector {
 public:
  typedef void (*CountCrashFunction)();
  typedef bool (*IsFeedbackAllowedFunction)();

  CrashCollector();

  virtual ~CrashCollector();

  // Initialize the crash collector for detection of crashes, given a
  // crash counting function, metrics collection enabled oracle, and
  // system logger facility.
  void Initialize(CountCrashFunction count_crash,
                  IsFeedbackAllowedFunction is_metrics_allowed,
                  SystemLogging *logger);

 protected:
  friend class CrashCollectorTest;
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityOverCore);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityOverNonCore);
  FRIEND_TEST(CrashCollectorTest, GetCrashDirectoryInfo);
  FRIEND_TEST(CrashCollectorTest, FormatDumpBasename);
  FRIEND_TEST(CrashCollectorTest, Initialize);

  // Set maximum enqueued crashes in a crash directory.
  static const int kMaxCrashDirectorySize;

  // For testing, set the directory always returned by
  // GetCreatedCrashDirectoryByEuid.
  void ForceCrashDirectory(const char *forced_directory) {
    forced_crash_directory_ = forced_directory;
  }

  FilePath GetCrashDirectoryInfo(uid_t process_euid,
                                 uid_t default_user_id,
                                 gid_t default_user_group,
                                 mode_t *mode,
                                 uid_t *directory_owner,
                                 gid_t *directory_group);
  bool GetUserInfoFromName(const std::string &name,
                           uid_t *uid,
                           gid_t *gid);
  // Determines the crash directory for given eud, and creates the
  // directory if necessary with appropriate permissions.  Returns
  // true whether or not directory needed to be created, false on any
  // failure.  If the crash directory is already full, returns false.
  bool GetCreatedCrashDirectoryByEuid(uid_t euid,
                                      FilePath *crash_file_path);

  // Format crash name based on components.
  std::string FormatDumpBasename(const std::string &exec_name,
                                 time_t timestamp,
                                 pid_t pid);

  // Check given crash directory still has remaining capacity for another
  // crash.
  bool CheckHasCapacity(const FilePath &crash_directory);

  CountCrashFunction count_crash_function_;
  IsFeedbackAllowedFunction is_feedback_allowed_function_;
  SystemLogging *logger_;
  const char *forced_crash_directory_;
};

#endif  // _CRASH_REPORTER_CRASH_COLLECTOR_H_
