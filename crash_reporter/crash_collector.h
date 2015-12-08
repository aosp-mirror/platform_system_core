/*
 * Copyright (C) 2012 The Android Open Source Project
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

#ifndef CRASH_REPORTER_CRASH_COLLECTOR_H_
#define CRASH_REPORTER_CRASH_COLLECTOR_H_

#include <sys/stat.h>

#include <map>
#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

// User crash collector.
class CrashCollector {
 public:
  typedef void (*CountCrashFunction)();
  typedef bool (*IsFeedbackAllowedFunction)();

  CrashCollector();

  virtual ~CrashCollector();

  // Initialize the crash collector for detection of crashes, given a
  // crash counting function, and metrics collection enabled oracle.
  void Initialize(CountCrashFunction count_crash,
                  IsFeedbackAllowedFunction is_metrics_allowed);

 protected:
  friend class CrashCollectorTest;
  FRIEND_TEST(ChromeCollectorTest, HandleCrash);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityCorrectBasename);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityStrangeNames);
  FRIEND_TEST(CrashCollectorTest, CheckHasCapacityUsual);
  FRIEND_TEST(CrashCollectorTest, GetCrashDirectoryInfo);
  FRIEND_TEST(CrashCollectorTest, GetCrashPath);
  FRIEND_TEST(CrashCollectorTest, GetLogContents);
  FRIEND_TEST(CrashCollectorTest, ForkExecAndPipe);
  FRIEND_TEST(CrashCollectorTest, FormatDumpBasename);
  FRIEND_TEST(CrashCollectorTest, Initialize);
  FRIEND_TEST(CrashCollectorTest, MetaData);
  FRIEND_TEST(CrashCollectorTest, Sanitize);
  FRIEND_TEST(CrashCollectorTest, WriteNewFile);
  FRIEND_TEST(ForkExecAndPipeTest, Basic);
  FRIEND_TEST(ForkExecAndPipeTest, NonZeroReturnValue);
  FRIEND_TEST(ForkExecAndPipeTest, BadOutputFile);
  FRIEND_TEST(ForkExecAndPipeTest, ExistingOutputFile);
  FRIEND_TEST(ForkExecAndPipeTest, BadExecutable);
  FRIEND_TEST(ForkExecAndPipeTest, StderrCaptured);
  FRIEND_TEST(ForkExecAndPipeTest, NULLParam);
  FRIEND_TEST(ForkExecAndPipeTest, NoParams);
  FRIEND_TEST(ForkExecAndPipeTest, SegFaultHandling);

  // Set maximum enqueued crashes in a crash directory.
  static const int kMaxCrashDirectorySize;

  // Writes |data| of |size| to |filename|, which must be a new file.
  // If the file already exists or writing fails, return a negative value.
  // Otherwise returns the number of bytes written.
  int WriteNewFile(const base::FilePath &filename, const char *data, int size);

  // Return a filename that has only [a-z0-1_] characters by mapping
  // all others into '_'.
  std::string Sanitize(const std::string &name);

  // For testing, set the directory always returned by
  // GetCreatedCrashDirectoryByEuid.
  void ForceCrashDirectory(const base::FilePath &forced_directory) {
    forced_crash_directory_ = forced_directory;
  }

  base::FilePath GetCrashDirectoryInfo(mode_t *mode,
                                       uid_t *directory_owner,
                                       gid_t *directory_group);
  bool GetUserInfoFromName(const std::string &name,
                           uid_t *uid,
                           gid_t *gid);

  // Determines the crash directory for given euid, and creates the
  // directory if necessary with appropriate permissions.  If
  // |out_of_capacity| is not nullptr, it is set to indicate if the call
  // failed due to not having capacity in the crash directory. Returns
  // true whether or not directory needed to be created, false on any
  // failure.  If the crash directory is at capacity, returns false.
  bool GetCreatedCrashDirectoryByEuid(uid_t euid,
                                      base::FilePath *crash_file_path,
                                      bool *out_of_capacity);

  // Format crash name based on components.
  std::string FormatDumpBasename(const std::string &exec_name,
                                 time_t timestamp,
                                 pid_t pid);

  // Create a file path to a file in |crash_directory| with the given
  // |basename| and |extension|.
  base::FilePath GetCrashPath(const base::FilePath &crash_directory,
                              const std::string &basename,
                              const std::string &extension);

  base::FilePath GetProcessPath(pid_t pid);
  bool GetSymlinkTarget(const base::FilePath &symlink,
                        base::FilePath *target);
  bool GetExecutableBaseNameFromPid(pid_t pid,
                                    std::string *base_name);

  // Check given crash directory still has remaining capacity for another
  // crash.
  bool CheckHasCapacity(const base::FilePath &crash_directory);

  // Write a log applicable to |exec_name| to |output_file| based on the
  // log configuration file at |config_path|.
  bool GetLogContents(const base::FilePath &config_path,
                      const std::string &exec_name,
                      const base::FilePath &output_file);

  // Add non-standard meta data to the crash metadata file.  Call
  // before calling WriteCrashMetaData.  Key must not contain "=" or
  // "\n" characters.  Value must not contain "\n" characters.
  void AddCrashMetaData(const std::string &key, const std::string &value);

  // Add a file to be uploaded to the crash reporter server. The file must
  // persist until the crash report is sent; ideally it should live in the same
  // place as the .meta file, so it can be cleaned up automatically.
  void AddCrashMetaUploadFile(const std::string &key, const std::string &path);

  // Add non-standard meta data to the crash metadata file.
  // Data added though this call will be uploaded to the crash reporter server,
  // appearing as a form field.
  void AddCrashMetaUploadData(const std::string &key, const std::string &value);

  // Write a file of metadata about crash.
  void WriteCrashMetaData(const base::FilePath &meta_path,
                          const std::string &exec_name,
                          const std::string &payload_path);

  // Returns true if the a crash test is currently running.
  bool IsCrashTestInProgress();
  // Returns true if we should consider ourselves to be running on a
  // developer image.
  bool IsDeveloperImage();

  CountCrashFunction count_crash_function_;
  IsFeedbackAllowedFunction is_feedback_allowed_function_;
  std::string extra_metadata_;
  base::FilePath forced_crash_directory_;
  base::FilePath log_config_path_;

 private:
  DISALLOW_COPY_AND_ASSIGN(CrashCollector);
};

#endif  // CRASH_REPORTER_CRASH_COLLECTOR_H_
