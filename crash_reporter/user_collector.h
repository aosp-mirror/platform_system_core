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

#ifndef CRASH_REPORTER_USER_COLLECTOR_H_
#define CRASH_REPORTER_USER_COLLECTOR_H_

#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash_collector.h"

class SystemLogging;

// User crash collector.
class UserCollector : public CrashCollector {
 public:
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
                  bool generate_diagnostics,
                  bool core2md_failure,
                  bool directory_failure,
                  const std::string &filter_in);

  ~UserCollector() override;

  // Enable collection.
  bool Enable() { return SetUpInternal(true); }

  // Disable collection.
  bool Disable() { return SetUpInternal(false); }

  // Handle a specific user crash.  Returns true on success.
  bool HandleCrash(const std::string &crash_attributes,
                   const char *force_exec);

 private:
  friend class UserCollectorTest;
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesBadPath);
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesBadPid);
  FRIEND_TEST(UserCollectorTest, CopyOffProcFilesOK);
  FRIEND_TEST(UserCollectorTest, GetExecutableBaseNameFromPid);
  FRIEND_TEST(UserCollectorTest, GetFirstLineWithPrefix);
  FRIEND_TEST(UserCollectorTest, GetIdFromStatus);
  FRIEND_TEST(UserCollectorTest, GetStateFromStatus);
  FRIEND_TEST(UserCollectorTest, GetProcessPath);
  FRIEND_TEST(UserCollectorTest, GetSymlinkTarget);
  FRIEND_TEST(UserCollectorTest, GetUserInfoFromName);
  FRIEND_TEST(UserCollectorTest, ParseCrashAttributes);
  FRIEND_TEST(UserCollectorTest, ShouldDumpChromeOverridesDeveloperImage);
  FRIEND_TEST(UserCollectorTest, ShouldDumpDeveloperImageOverridesConsent);
  FRIEND_TEST(UserCollectorTest, ShouldDumpUseConsentProductionImage);
  FRIEND_TEST(UserCollectorTest, ValidateProcFiles);
  FRIEND_TEST(UserCollectorTest, ValidateCoreFile);

  // Enumeration to pass to GetIdFromStatus.  Must match the order
  // that the kernel lists IDs in the status file.
  enum IdKind {
    kIdReal = 0,  // uid and gid
    kIdEffective = 1,  // euid and egid
    kIdSet = 2,  // suid and sgid
    kIdFileSystem = 3,  // fsuid and fsgid
    kIdMax
  };

  enum ErrorType {
    kErrorNone,
    kErrorSystemIssue,
    kErrorReadCoreData,
    kErrorUnusableProcFiles,
    kErrorInvalidCoreFile,
    kErrorUnsupported32BitCoreFile,
    kErrorCore2MinidumpConversion,
  };

  static const int kForkProblem = 255;

  // Returns an error type signature for a given |error_type| value,
  // which is reported to the crash server along with the
  // crash_reporter-user-collection signature.
  std::string GetErrorTypeSignature(ErrorType error_type) const;

  bool SetUpInternal(bool enabled);

  // Returns, via |line|, the first line in |lines| that starts with |prefix|.
  // Returns true if a line is found, or false otherwise.
  bool GetFirstLineWithPrefix(const std::vector<std::string> &lines,
                              const char *prefix, std::string *line);

  // Returns the identifier of |kind|, via |id|, found in |status_lines| on
  // the line starting with |prefix|. |status_lines| contains the lines in
  // the status file. Returns true if the identifier can be determined.
  bool GetIdFromStatus(const char *prefix,
                       IdKind kind,
                       const std::vector<std::string> &status_lines,
                       int *id);

  // Returns the process state, via |state|, found in |status_lines|, which
  // contains the lines in the status file. Returns true if the process state
  // can be determined.
  bool GetStateFromStatus(const std::vector<std::string> &status_lines,
                          std::string *state);

  void LogCollectionError(const std::string &error_message);
  void EnqueueCollectionErrorLog(pid_t pid, ErrorType error_type,
                                 const std::string &exec_name);

  bool CopyOffProcFiles(pid_t pid, const base::FilePath &container_dir);

  // Validates the proc files at |container_dir| and returns true if they
  // are usable for the core-to-minidump conversion later. For instance, if
  // a process is reaped by the kernel before the copying of its proc files
  // takes place, some proc files like /proc/<pid>/maps may contain nothing
  // and thus become unusable.
  bool ValidateProcFiles(const base::FilePath &container_dir) const;

  // Validates the core file at |core_path| and returns kErrorNone if
  // the file contains the ELF magic bytes and an ELF class that matches the
  // platform (i.e. 32-bit ELF on a 32-bit platform or 64-bit ELF on a 64-bit
  // platform), which is due to the limitation in core2md. It returns an error
  // type otherwise.
  ErrorType ValidateCoreFile(const base::FilePath &core_path) const;

  // Determines the crash directory for given pid based on pid's owner,
  // and creates the directory if necessary with appropriate permissions.
  // Returns true whether or not directory needed to be created, false on
  // any failure.
  bool GetCreatedCrashDirectory(pid_t pid, uid_t supplied_ruid,
                                base::FilePath *crash_file_path,
                                bool *out_of_capacity);
  bool CopyStdinToCoreFile(const base::FilePath &core_path);
  bool RunCoreToMinidump(const base::FilePath &core_path,
                         const base::FilePath &procfs_directory,
                         const base::FilePath &minidump_path,
                         const base::FilePath &temp_directory);
  ErrorType ConvertCoreToMinidump(pid_t pid,
                                  const base::FilePath &container_dir,
                                  const base::FilePath &core_path,
                                  const base::FilePath &minidump_path);
  ErrorType ConvertAndEnqueueCrash(pid_t pid, const std::string &exec_name,
                                   uid_t supplied_ruid, bool *out_of_capacity);
  bool ParseCrashAttributes(const std::string &crash_attributes,
                            pid_t *pid, int *signal, uid_t *uid, gid_t *gid,
                            std::string *kernel_supplied_name);

  bool ShouldDump(bool has_owner_consent,
                  bool is_developer,
                  std::string *reason);

  bool generate_diagnostics_;
  std::string our_path_;
  bool initialized_;

  bool core2md_failure_;
  bool directory_failure_;
  std::string filter_in_;

  static const char *kUserId;
  static const char *kGroupId;

  DISALLOW_COPY_AND_ASSIGN(UserCollector);
};

#endif  // CRASH_REPORTER_USER_COLLECTOR_H_
