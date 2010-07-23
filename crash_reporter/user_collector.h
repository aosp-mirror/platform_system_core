// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef _CRASH_REPORTER_USER_COLLECTOR_H_
#define _CRASH_REPORTER_USER_COLLECTOR_H_

#include <string>

#include "crash-reporter/system_logging.h"
#include "gtest/gtest_prod.h"  // for FRIEND_TEST

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
  // Crash detection/reporting is not enabled until Enable is called.
  // |generate_diagnostics| is used to indicate whether or not to try
  // to generate a minidump from crashes.
  void Initialize(CountCrashFunction count_crash,
                  const std::string &our_path,
                  IsFeedbackAllowedFunction is_metrics_allowed,
                  SystemLogging *logger,
                  bool generate_diagnostics);

  virtual ~UserCollector();

  // Enable collection.
  bool Enable() { return SetUpInternal(true); }

  // Disable collection.
  bool Disable() { return SetUpInternal(false); }

  // Handle a specific user crash.  Returns true on success.
  bool HandleCrash(int signal, int pid, const char *force_exec);

  // Set (override the default) core file pattern.
  void set_core_pattern_file(const std::string &pattern) {
    core_pattern_file_ = pattern;
  }

 private:
  friend class UserCollectorTest;
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesBadPath);
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesBadPid);
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesOK);
  FRIEND_TEST(UserCollectorTest, FormatDumpBasename);
  FRIEND_TEST(UserCollectorTest, GetCrashDirectoryInfo);
  FRIEND_TEST(UserCollectorTest, GetIdFromStatus);
  FRIEND_TEST(UserCollectorTest, GetProcessPath);
  FRIEND_TEST(UserCollectorTest, GetSymlinkTarget);
  FRIEND_TEST(UserCollectorTest, GetUserInfoFromName);

  // Enumeration to pass to GetIdFromStatus.  Must match the order
  // that the kernel lists IDs in the status file.
  enum IdKind {
    kIdReal = 0,  // uid and gid
    kIdEffective = 1,  // euid and egid
    kIdSet = 2,  // suid and sgid
    kIdFileSystem = 3,  // fsuid and fsgid
    kIdMax
  };

  std::string GetPattern(bool enabled) const;
  bool SetUpInternal(bool enabled);

  FilePath GetProcessPath(pid_t pid);
  bool GetSymlinkTarget(const FilePath &symlink,
                        FilePath *target);
  bool GetExecutableBaseNameFromPid(uid_t pid,
                                    std::string *base_name);
  bool GetIdFromStatus(const char *prefix,
                       IdKind kind,
                       const std::string &status_contents,
                       int *id);
  bool GetUserInfoFromName(const std::string &name,
                           uid_t *uid,
                           gid_t *gid);
  bool CopyOffProcFiles(pid_t pid, const FilePath &process_map);
  FilePath GetCrashDirectoryInfo(uid_t process_euid,
                                 uid_t default_user_id,
                                 gid_t default_user_group,
                                 mode_t *mode,
                                 uid_t *directory_owner,
                                 gid_t *directory_group);
  // Determines the crash directory for given pid based on pid's owner,
  // and creates the directory if necessary with appropriate permissions.
  // Returns true whether or not directory needed to be created, false on
  // any failure.
  bool GetCreatedCrashDirectory(pid_t pid,
                                FilePath *crash_file_path);
  std::string FormatDumpBasename(const std::string &exec_name,
                                 time_t timestamp,
                                 pid_t pid);
  bool CopyStdinToCoreFile(const FilePath &core_path);
  bool ConvertCoreToMinidump(const FilePath &core_path,
                             const FilePath &procfs_directory,
                             const FilePath &minidump_path,
                             const FilePath &temp_directory);
  bool GenerateDiagnostics(pid_t pid, const std::string &exec_name);

  bool generate_diagnostics_;
  std::string core_pattern_file_;
  CountCrashFunction count_crash_function_;
  std::string our_path_;
  bool initialized_;
  IsFeedbackAllowedFunction is_feedback_allowed_function_;
  SystemLogging *logger_;

  static const char *kUserId;
  static const char *kGroupId;
};

#endif  // _CRASH_REPORTER_USER_COLLECTOR_H_
