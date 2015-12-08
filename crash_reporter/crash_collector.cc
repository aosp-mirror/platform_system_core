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

#include "crash_collector.h"

#include <dirent.h>
#include <fcntl.h>  // For file creation modes.
#include <inttypes.h>
#include <linux/limits.h>  // PATH_MAX
#include <pwd.h>  // For struct passwd.
#include <sys/types.h>  // for mode_t.
#include <sys/wait.h>  // For waitpid.
#include <unistd.h>  // For execv and fork.

#include <set>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/posix/eintr_wrapper.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/key_value_store.h>
#include <brillo/process.h>

namespace {

const char kCollectChromeFile[] =
    "/mnt/stateful_partition/etc/collect_chrome_crashes";
const char kCrashTestInProgressPath[] =
    "/data/misc/crash_reporter/tmp/crash-test-in-progress";
const char kDefaultLogConfig[] = "/etc/crash_reporter_logs.conf";
const char kDefaultUserName[] = "chronos";
const char kLeaveCoreFile[] = "/data/misc/crash_reporter/.leave_core";
const char kShellPath[] = "/system/bin/sh";
const char kSystemCrashPath[] = "/data/misc/crash_reporter/crash";
const char kUploadVarPrefix[] = "upload_var_";
const char kUploadFilePrefix[] = "upload_file_";

// Normally this path is not used.  Unfortunately, there are a few edge cases
// where we need this.  Any process that runs as kDefaultUserName that crashes
// is consider a "user crash".  That includes the initial Chrome browser that
// runs the login screen.  If that blows up, there is no logged in user yet,
// so there is no per-user dir for us to stash things in.  Instead we fallback
// to this path as it is at least encrypted on a per-system basis.
//
// This also comes up when running autotests.  The GUI is sitting at the login
// screen while tests are sshing in, changing users, and triggering crashes as
// the user (purposefully).
const char kFallbackUserCrashPath[] = "/home/chronos/crash";

// Directory mode of the user crash spool directory.
const mode_t kUserCrashPathMode = 0755;

// Directory mode of the system crash spool directory.
const mode_t kSystemCrashPathMode = 01755;

const uid_t kRootOwner = 0;
const uid_t kRootGroup = 0;

}  // namespace

// Maximum crash reports per crash spool directory.  Note that this is
// a separate maximum from the maximum rate at which we upload these
// diagnostics.  The higher this rate is, the more space we allow for
// core files, minidumps, and kcrash logs, and equivalently the more
// processor and I/O bandwidth we dedicate to handling these crashes when
// many occur at once.  Also note that if core files are configured to
// be left on the file system, we stop adding crashes when either the
// number of core files or minidumps reaches this number.
const int CrashCollector::kMaxCrashDirectorySize = 32;

using base::FilePath;
using base::StringPrintf;

CrashCollector::CrashCollector()
    : log_config_path_(kDefaultLogConfig) {
}

CrashCollector::~CrashCollector() {
}

void CrashCollector::Initialize(
    CrashCollector::CountCrashFunction count_crash_function,
    CrashCollector::IsFeedbackAllowedFunction is_feedback_allowed_function) {
  CHECK(count_crash_function);
  CHECK(is_feedback_allowed_function);

  count_crash_function_ = count_crash_function;
  is_feedback_allowed_function_ = is_feedback_allowed_function;
}

int CrashCollector::WriteNewFile(const FilePath &filename,
                                 const char *data,
                                 int size) {
  int fd = HANDLE_EINTR(open(filename.value().c_str(),
                             O_CREAT | O_WRONLY | O_TRUNC | O_EXCL, 0666));
  if (fd < 0) {
    return -1;
  }

  int rv = base::WriteFileDescriptor(fd, data, size) ? size : -1;
  IGNORE_EINTR(close(fd));
  return rv;
}

std::string CrashCollector::Sanitize(const std::string &name) {
  // Make sure the sanitized name does not include any periods.
  // The logic in crash_sender relies on this.
  std::string result = name;
  for (size_t i = 0; i < name.size(); ++i) {
    if (!isalnum(result[i]) && result[i] != '_')
      result[i] = '_';
  }
  return result;
}

std::string CrashCollector::FormatDumpBasename(const std::string &exec_name,
                                               time_t timestamp,
                                               pid_t pid) {
  struct tm tm;
  localtime_r(&timestamp, &tm);
  std::string sanitized_exec_name = Sanitize(exec_name);
  return StringPrintf("%s.%04d%02d%02d.%02d%02d%02d.%d",
                      sanitized_exec_name.c_str(),
                      tm.tm_year + 1900,
                      tm.tm_mon + 1,
                      tm.tm_mday,
                      tm.tm_hour,
                      tm.tm_min,
                      tm.tm_sec,
                      pid);
}

FilePath CrashCollector::GetCrashPath(const FilePath &crash_directory,
                                      const std::string &basename,
                                      const std::string &extension) {
  return crash_directory.Append(StringPrintf("%s.%s",
                                             basename.c_str(),
                                             extension.c_str()));
}

FilePath CrashCollector::GetCrashDirectoryInfo(
    mode_t *mode,
    uid_t *directory_owner,
    gid_t *directory_group) {
  *mode = kSystemCrashPathMode;
  *directory_owner = kRootOwner;
  *directory_group = kRootGroup;
  return FilePath(kSystemCrashPath);
}

bool CrashCollector::GetUserInfoFromName(const std::string &name,
                                         uid_t *uid,
                                         gid_t *gid) {
  char storage[256];
  struct passwd passwd_storage;
  struct passwd *passwd_result = nullptr;

  if (getpwnam_r(name.c_str(), &passwd_storage, storage, sizeof(storage),
                 &passwd_result) != 0 || passwd_result == nullptr) {
    LOG(ERROR) << "Cannot find user named " << name;
    return false;
  }

  *uid = passwd_result->pw_uid;
  *gid = passwd_result->pw_gid;
  return true;
}

bool CrashCollector::GetCreatedCrashDirectoryByEuid(uid_t euid,
                                                    FilePath *crash_directory,
                                                    bool *out_of_capacity) {
  if (out_of_capacity) *out_of_capacity = false;

  // For testing.
  if (!forced_crash_directory_.empty()) {
    *crash_directory = forced_crash_directory_;
    return true;
  }

  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;
  *crash_directory =
      GetCrashDirectoryInfo(&directory_mode,
                            &directory_owner,
                            &directory_group);

  if (!base::PathExists(*crash_directory)) {
    // Create the spool directory with the appropriate mode (regardless of
    // umask) and ownership.
    mode_t old_mask = umask(0);
    if (mkdir(crash_directory->value().c_str(), directory_mode) < 0 ||
        chown(crash_directory->value().c_str(),
              directory_owner,
              directory_group) < 0) {
      LOG(ERROR) << "Unable to create appropriate crash directory";
      return false;
    }
    umask(old_mask);
  }

  if (!base::PathExists(*crash_directory)) {
    LOG(ERROR) << "Unable to create crash directory "
               << crash_directory->value().c_str();
    return false;
  }

  if (!CheckHasCapacity(*crash_directory)) {
    if (out_of_capacity) *out_of_capacity = true;
    LOG(ERROR) << "Directory " << crash_directory->value()
               << " is out of capacity.";
    return false;
  }

  return true;
}

FilePath CrashCollector::GetProcessPath(pid_t pid) {
  return FilePath(StringPrintf("/proc/%d", pid));
}

bool CrashCollector::GetSymlinkTarget(const FilePath &symlink,
                                      FilePath *target) {
  ssize_t max_size = 64;
  std::vector<char> buffer;

  while (true) {
    buffer.resize(max_size + 1);
    ssize_t size = readlink(symlink.value().c_str(), buffer.data(), max_size);
    if (size < 0) {
      int saved_errno = errno;
      LOG(ERROR) << "Readlink failed on " << symlink.value() << " with "
                 << saved_errno;
      return false;
    }

    buffer[size] = 0;
    if (size == max_size) {
      max_size *= 2;
      if (max_size > PATH_MAX) {
        return false;
      }
      continue;
    }
    break;
  }

  *target = FilePath(buffer.data());
  return true;
}

bool CrashCollector::GetExecutableBaseNameFromPid(pid_t pid,
                                                 std::string *base_name) {
  FilePath target;
  FilePath process_path = GetProcessPath(pid);
  FilePath exe_path = process_path.Append("exe");
  if (!GetSymlinkTarget(exe_path, &target)) {
    LOG(INFO) << "GetSymlinkTarget failed - Path " << process_path.value()
              << " DirectoryExists: "
              << base::DirectoryExists(process_path);
    // Try to further diagnose exe readlink failure cause.
    struct stat buf;
    int stat_result = stat(exe_path.value().c_str(), &buf);
    int saved_errno = errno;
    if (stat_result < 0) {
      LOG(INFO) << "stat " << exe_path.value() << " failed: " << stat_result
                << " " << saved_errno;
    } else {
      LOG(INFO) << "stat " << exe_path.value() << " succeeded: st_mode="
                << buf.st_mode;
    }
    return false;
  }
  *base_name = target.BaseName().value();
  return true;
}

// Return true if the given crash directory has not already reached
// maximum capacity.
bool CrashCollector::CheckHasCapacity(const FilePath &crash_directory) {
  DIR* dir = opendir(crash_directory.value().c_str());
  if (!dir) {
    LOG(WARNING) << "Unable to open crash directory "
                 << crash_directory.value();
    return false;
  }
  struct dirent ent_buf;
  struct dirent* ent;
  bool full = false;
  std::set<std::string> basenames;
  while (readdir_r(dir, &ent_buf, &ent) == 0 && ent) {
    if ((strcmp(ent->d_name, ".") == 0) ||
        (strcmp(ent->d_name, "..") == 0))
      continue;

    std::string filename(ent->d_name);
    size_t last_dot = filename.rfind(".");
    std::string basename;
    // If there is a valid looking extension, use the base part of the
    // name.  If the only dot is the first byte (aka a dot file), treat
    // it as unique to avoid allowing a directory full of dot files
    // from accumulating.
    if (last_dot != std::string::npos && last_dot != 0)
      basename = filename.substr(0, last_dot);
    else
      basename = filename;
    basenames.insert(basename);

    if (basenames.size() >= static_cast<size_t>(kMaxCrashDirectorySize)) {
      LOG(WARNING) << "Crash directory " << crash_directory.value()
                   << " already full with " << kMaxCrashDirectorySize
                   << " pending reports";
      full = true;
      break;
    }
  }
  closedir(dir);
  return !full;
}

bool CrashCollector::GetLogContents(const FilePath &config_path,
                                    const std::string &exec_name,
                                    const FilePath &output_file) {
  brillo::KeyValueStore store;
  if (!store.Load(config_path)) {
    LOG(INFO) << "Unable to read log configuration file "
              << config_path.value();
    return false;
  }

  std::string command;
  if (!store.GetString(exec_name, &command))
    return false;

  brillo::ProcessImpl diag_process;
  diag_process.AddArg(kShellPath);
  diag_process.AddStringOption("-c", command);
  diag_process.RedirectOutput(output_file.value());

  const int result = diag_process.Run();
  if (result != 0) {
    LOG(INFO) << "Log command \"" << command << "\" exited with " << result;
    return false;
  }
  return true;
}

void CrashCollector::AddCrashMetaData(const std::string &key,
                                      const std::string &value) {
  extra_metadata_.append(StringPrintf("%s=%s\n", key.c_str(), value.c_str()));
}

void CrashCollector::AddCrashMetaUploadFile(const std::string &key,
                                            const std::string &path) {
  if (!path.empty())
    AddCrashMetaData(kUploadFilePrefix + key, path);
}

void CrashCollector::AddCrashMetaUploadData(const std::string &key,
                                            const std::string &value) {
  if (!value.empty())
    AddCrashMetaData(kUploadVarPrefix + key, value);
}

void CrashCollector::WriteCrashMetaData(const FilePath &meta_path,
                                        const std::string &exec_name,
                                        const std::string &payload_path) {
  int64_t payload_size = -1;
  base::GetFileSize(FilePath(payload_path), &payload_size);
  std::string meta_data = StringPrintf("%sexec_name=%s\n"
                                       "payload=%s\n"
                                       "payload_size=%" PRId64 "\n"
                                       "done=1\n",
                                       extra_metadata_.c_str(),
                                       exec_name.c_str(),
                                       payload_path.c_str(),
                                       payload_size);
  // We must use WriteNewFile instead of base::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(meta_path, meta_data.c_str(), meta_data.size()) < 0) {
    LOG(ERROR) << "Unable to write " << meta_path.value();
  }
}

bool CrashCollector::IsCrashTestInProgress() {
  return base::PathExists(FilePath(kCrashTestInProgressPath));
}

bool CrashCollector::IsDeveloperImage() {
  // If we're testing crash reporter itself, we don't want to special-case
  // for developer images.
  if (IsCrashTestInProgress())
    return false;
  return base::PathExists(FilePath(kLeaveCoreFile));
}
