// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <grp.h>  // For struct group.
#include <pwd.h>  // For struct passwd.
#include <sys/types.h>  // For getpwuid_r and getgrnam_r.

#include <string>

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash-reporter/user_collector.h"
#include "metrics/metrics_library.h"

// This procfs file is used to cause kernel core file writing to
// instead pipe the core file into a user space process.  See
// core(5) man page.
static const char kCorePatternFile[] = "/proc/sys/kernel/core_pattern";
static const char kCoreToMinidumpConverterPath[] = "/usr/bin/core2md";
static const char kDefaultUserName[] = "chronos";
static const char kLeaveCoreFile[] = "/root/.leave_core";
static const char kSystemCrashPath[] = "/var/spool/crash";
static const char kUserCrashPath[] = "/home/chronos/user/crash";

// Directory mode of the user crash spool directory.
static const mode_t kUserCrashPathMode = 0755;

// Directory mode of the system crash spool directory.
static const mode_t kSystemCrashPathMode = 01755;

static const uid_t kRootOwner = 0;
static const uid_t kRootGroup = 0;

const char *UserCollector::kUserId = "Uid:\t";
const char *UserCollector::kGroupId = "Gid:\t";

UserCollector::UserCollector()
    : generate_diagnostics_(false),
      core_pattern_file_(kCorePatternFile),
      count_crash_function_(NULL),
      initialized_(false),
      is_feedback_allowed_function_(NULL),
      logger_(NULL) {
}

void UserCollector::Initialize(
    UserCollector::CountCrashFunction count_crash_function,
    const std::string &our_path,
    UserCollector::IsFeedbackAllowedFunction is_feedback_allowed_function,
    SystemLogging *logger,
    bool generate_diagnostics) {
  CHECK(count_crash_function != NULL);
  CHECK(is_feedback_allowed_function != NULL);
  CHECK(logger != NULL);

  count_crash_function_ = count_crash_function;
  our_path_ = our_path;
  is_feedback_allowed_function_ = is_feedback_allowed_function;
  logger_ = logger;
  initialized_ = true;
  generate_diagnostics_ = generate_diagnostics;
}

UserCollector::~UserCollector() {
}

std::string UserCollector::GetPattern(bool enabled) const {
  if (enabled) {
    return StringPrintf("|%s --signal=%%s --pid=%%p", our_path_.c_str());
  } else {
    return "core";
  }
}

bool UserCollector::SetUpInternal(bool enabled) {
  CHECK(initialized_);
  logger_->LogInfo("%s crash handling", enabled ? "Enabling" : "Disabling");
  std::string pattern = GetPattern(enabled);
  if (file_util::WriteFile(FilePath(core_pattern_file_),
                           pattern.c_str(),
                           pattern.length()) !=
      static_cast<int>(pattern.length())) {
    logger_->LogError("Unable to write %s", core_pattern_file_.c_str());
    return false;
  }
  return true;
}

FilePath UserCollector::GetProcessPath(pid_t pid) {
  return FilePath(StringPrintf("/proc/%d", pid));
}

bool UserCollector::GetSymlinkTarget(const FilePath &symlink,
                                     FilePath *target) {
  int max_size = 32;
  scoped_array<char> buffer;
  while (true) {
    buffer.reset(new char[max_size + 1]);
    ssize_t size = readlink(symlink.value().c_str(), buffer.get(), max_size);
    if (size < 0) {
      return false;
    }
    buffer[size] = 0;
    if (size == max_size) {
      // Avoid overflow when doubling.
      if (max_size * 2 > max_size) {
        max_size *= 2;
        continue;
      } else {
        return false;
      }
    }
    break;
  }

  *target = FilePath(buffer.get());
  return true;
}

bool UserCollector::GetExecutableBaseNameFromPid(uid_t pid,
                                                 std::string *base_name) {
  FilePath target;
  if (!GetSymlinkTarget(GetProcessPath(pid).Append("exe"), &target))
    return false;
  *base_name = target.BaseName().value();
  return true;
}

bool UserCollector::GetIdFromStatus(const char *prefix,
                                    IdKind kind,
                                    const std::string &status_contents,
                                    int *id) {
  // From fs/proc/array.c:task_state(), this file contains:
  // \nUid:\t<uid>\t<euid>\t<suid>\t<fsuid>\n
  std::vector<std::string> status_lines;
  SplitString(status_contents, '\n', &status_lines);
  std::vector<std::string>::iterator line_iterator;
  for (line_iterator = status_lines.begin();
       line_iterator != status_lines.end();
       ++line_iterator) {
    if (line_iterator->find(prefix) == 0)
      break;
  }
  if (line_iterator == status_lines.end()) {
    return false;
  }
  std::string id_substring = line_iterator->substr(strlen(prefix),
                                                   std::string::npos);
  std::vector<std::string> ids;
  SplitString(id_substring, '\t', &ids);
  if (ids.size() != kIdMax || kind < 0 || kind >= kIdMax) {
    return false;
  }
  const char *number = ids[kind].c_str();
  char *end_number = NULL;
  *id = strtol(number, &end_number, 10);
  if (*end_number != '\0')
    return false;
  return true;
}

bool UserCollector::GetUserInfoFromName(const std::string &name,
                                        uid_t *uid,
                                        gid_t *gid) {
  char storage[256];
  struct passwd passwd_storage;
  struct passwd *passwd_result = NULL;

  if (getpwnam_r(name.c_str(), &passwd_storage, storage, sizeof(storage),
                 &passwd_result) != 0 || passwd_result == NULL) {
    logger_->LogError("Cannot find user named %s", name.c_str());
    return false;
  }

  *uid = passwd_result->pw_uid;
  *gid = passwd_result->pw_gid;
  return true;
}

bool UserCollector::CopyOffProcFiles(pid_t pid,
                                     const FilePath &container_dir) {
  if (!file_util::CreateDirectory(container_dir)) {
    logger_->LogInfo("Could not create %s", container_dir.value().c_str());
    return false;
  }
  FilePath process_path = GetProcessPath(pid);
  if (!file_util::PathExists(process_path)) {
    logger_->LogWarning("Path %s does not exist",
                        process_path.value().c_str());
    return false;
  }
  static const char *proc_files[] = {
    "auxv",
    "cmdline",
    "environ",
    "maps",
    "status"
  };
  for (unsigned i = 0; i < arraysize(proc_files); ++i) {
    if (!file_util::CopyFile(process_path.Append(proc_files[i]),
                             container_dir.Append(proc_files[i]))) {
      logger_->LogWarning("Could not copy %s file", proc_files[i]);
      return false;
    }
  }
  return true;
}

FilePath UserCollector::GetCrashDirectoryInfo(
    uid_t process_euid,
    uid_t default_user_id,
    gid_t default_user_group,
    mode_t *mode,
    uid_t *directory_owner,
    gid_t *directory_group) {
  if (process_euid == default_user_id) {
    *mode = kUserCrashPathMode;
    *directory_owner = default_user_id;
    *directory_group = default_user_group;
    return FilePath(kUserCrashPath);
  } else {
    *mode = kSystemCrashPathMode;
    *directory_owner = kRootOwner;
    *directory_group = kRootGroup;
    return FilePath(kSystemCrashPath);
  }
}

bool UserCollector::GetCreatedCrashDirectory(pid_t pid,
                                             FilePath *crash_file_path) {
  FilePath process_path = GetProcessPath(pid);
  std::string status;
  if (!file_util::ReadFileToString(process_path.Append("status"),
                                   &status)) {
    logger_->LogError("Could not read status file");
    return false;
  }
  int process_euid;
  if (!GetIdFromStatus(kUserId, kIdEffective, status, &process_euid)) {
    logger_->LogError("Could not find euid in status file");
    return false;
  }
  uid_t default_user_id;
  gid_t default_user_group;
  if (!GetUserInfoFromName(kDefaultUserName,
                           &default_user_id,
                           &default_user_group)) {
    logger_->LogError("Could not find default user info");
    return false;
  }
  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;
  *crash_file_path =
      GetCrashDirectoryInfo(process_euid,
                            default_user_id,
                            default_user_group,
                            &directory_mode,
                            &directory_owner,
                            &directory_group);


  if (!file_util::PathExists(*crash_file_path)) {
    // Create the spool directory with the appropriate mode (regardless of
    // umask) and ownership.
    mode_t old_mask = umask(0);
    if (mkdir(crash_file_path->value().c_str(), directory_mode) < 0 ||
        chown(crash_file_path->value().c_str(),
              directory_owner,
              directory_group) < 0) {
      logger_->LogError("Unable to create appropriate crash directory");
      return false;
    }
    umask(old_mask);
  }

  if (!file_util::PathExists(*crash_file_path)) {
    logger_->LogError("Unable to create crash directory %s",
                      crash_file_path->value().c_str());
    return false;
  }


  return true;
}

std::string UserCollector::FormatDumpBasename(const std::string &exec_name,
                                              time_t timestamp,
                                              pid_t pid) {
  struct tm tm;
  localtime_r(&timestamp, &tm);
  return StringPrintf("%s.%04d%02d%02d.%02d%02d%02d.%d",
                      exec_name.c_str(),
                      tm.tm_year + 1900,
                      tm.tm_mon + 1,
                      tm.tm_mday,
                      tm.tm_hour,
                      tm.tm_min,
                      tm.tm_sec,
                      pid);
}

bool UserCollector::CopyStdinToCoreFile(const FilePath &core_path) {
  // Copy off all stdin to a core file.
  FilePath stdin_path("/dev/fd/0");
  if (file_util::CopyFile(stdin_path, core_path)) {
    return true;
  }

  logger_->LogError("Could not write core file");
  // If the file system was full, make sure we remove any remnants.
  file_util::Delete(core_path, false);
  return false;
}

bool UserCollector::ConvertCoreToMinidump(const FilePath &core_path,
                                          const FilePath &procfs_directory,
                                          const FilePath &minidump_path,
                                          const FilePath &temp_directory) {
  // TODO(kmixter): Rewrite to use process_util once it's included in
  // libchrome.
  FilePath output_path = temp_directory.Append("output");
  std::string core2md_command =
      StringPrintf("\"%s\" \"%s\" \"%s\" \"%s\" > \"%s\" 2>&1",
                   kCoreToMinidumpConverterPath,
                   core_path.value().c_str(),
                   procfs_directory.value().c_str(),
                   minidump_path.value().c_str(),
                   output_path.value().c_str());
  int errorlevel = system(core2md_command.c_str());

  std::string output;
  file_util::ReadFileToString(output_path, &output);
  if (errorlevel != 0) {
    logger_->LogInfo("Problem during %s [result=%d]: %s",
                     core2md_command.c_str(),
                     errorlevel,
                     output.c_str());
    return false;
  }

  if (!file_util::PathExists(minidump_path)) {
    logger_->LogError("Minidump file %s was not created",
                      minidump_path.value().c_str());
    return false;
  }
  return true;
}

bool UserCollector::GenerateDiagnostics(pid_t pid,
                                        const std::string &exec_name) {
  FilePath container_dir("/tmp");
  container_dir = container_dir.Append(
      StringPrintf("crash_reporter.%d", pid));

  if (!CopyOffProcFiles(pid, container_dir)) {
    file_util::Delete(container_dir, true);
    return false;
  }

  FilePath spool_path;
  if (!GetCreatedCrashDirectory(pid, &spool_path)) {
    file_util::Delete(container_dir, true);
    return false;
  }
  std::string dump_basename = FormatDumpBasename(exec_name, time(NULL), pid);
  FilePath core_path = spool_path.Append(
      StringPrintf("%s.core", dump_basename.c_str()));

  if (!CopyStdinToCoreFile(core_path)) {
    file_util::Delete(container_dir, true);
    return false;
  }

  FilePath minidump_path = spool_path.Append(
      StringPrintf("%s.dmp", dump_basename.c_str()));

  bool conversion_result = true;
  if (!ConvertCoreToMinidump(core_path,
                             container_dir,  // procfs directory
                             minidump_path,
                             container_dir)) {  // temporary directory
    // Note we leave the container directory for inspection.
    conversion_result = false;
  }

  if (conversion_result) {
    logger_->LogInfo("Stored minidump to %s", minidump_path.value().c_str());
  }

  if (!file_util::PathExists(FilePath(kLeaveCoreFile))) {
    file_util::Delete(core_path, false);
  } else {
    logger_->LogInfo("Leaving core file at %s", core_path.value().c_str());
  }

  return conversion_result;
}

bool UserCollector::HandleCrash(int signal, int pid, const char *force_exec) {
  CHECK(initialized_);
  std::string exec;
  if (force_exec) {
    exec.assign(force_exec);
  } else if (!GetExecutableBaseNameFromPid(pid, &exec)) {
    // If for some reason we don't have the base name, avoid completely
    // failing by indicating an unknown name.
    exec = "unknown";
  }
  logger_->LogWarning("Received crash notification for %s[%d] sig %d",
                      exec.c_str(), pid, signal);

  if (is_feedback_allowed_function_()) {
    count_crash_function_();
  }

  if (generate_diagnostics_) {
    return GenerateDiagnostics(pid, exec);
  }
  return true;
}
