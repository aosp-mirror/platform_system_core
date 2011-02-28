// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_collector.h"

#include <dirent.h>
#include <fcntl.h>  // For file creation modes.
#include <pwd.h>  // For struct passwd.
#include <sys/types.h>  // for mode_t.
#include <sys/wait.h>  // For waitpid.
#include <unistd.h>  // For execv and fork.

#include <set>

#include "base/eintr_wrapper.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash-reporter/system_logging.h"

static const char kDefaultUserName[] = "chronos";
static const char kLsbRelease[] = "/etc/lsb-release";
static const char kShellPath[] = "/bin/sh";
static const char kSystemCrashPath[] = "/var/spool/crash";
static const char kUserCrashPath[] = "/home/chronos/user/crash";
static const char kCrashTestInProgressPath[] = "/tmp/crash-test-in-progress";

// Directory mode of the user crash spool directory.
static const mode_t kUserCrashPathMode = 0755;

// Directory mode of the system crash spool directory.
static const mode_t kSystemCrashPathMode = 01755;

static const uid_t kRootOwner = 0;
static const uid_t kRootGroup = 0;

// Maximum crash reports per crash spool directory.  Note that this is
// a separate maximum from the maximum rate at which we upload these
// diagnostics.  The higher this rate is, the more space we allow for
// core files, minidumps, and kcrash logs, and equivalently the more
// processor and I/O bandwidth we dedicate to handling these crashes when
// many occur at once.  Also note that if core files are configured to
// be left on the file system, we stop adding crashes when either the
// number of core files or minidumps reaches this number.
const int CrashCollector::kMaxCrashDirectorySize = 32;

CrashCollector::CrashCollector()
    : forced_crash_directory_(NULL),
      lsb_release_(kLsbRelease) {
}

CrashCollector::~CrashCollector() {
}

void CrashCollector::Initialize(
    CrashCollector::CountCrashFunction count_crash_function,
    CrashCollector::IsFeedbackAllowedFunction is_feedback_allowed_function,
    SystemLogging *logger) {
  CHECK(count_crash_function != NULL);
  CHECK(is_feedback_allowed_function != NULL);
  CHECK(logger != NULL);

  count_crash_function_ = count_crash_function;
  is_feedback_allowed_function_ = is_feedback_allowed_function;
  logger_ = logger;
}

int CrashCollector::WriteNewFile(const FilePath &filename,
                                 const char *data,
                                 int size) {
  int fd = HANDLE_EINTR(open(filename.value().c_str(),
                             O_CREAT | O_WRONLY | O_TRUNC | O_EXCL, 0666));
  if (fd < 0) {
    return -1;
  }

  int rv = file_util::WriteFileDescriptor(fd, data, size);
  HANDLE_EINTR(close(fd));
  return rv;
}

int CrashCollector::ForkExecAndPipe(std::vector<const char *> &arguments,
                                    const char *output_file) {
  // Copy off a writeable version of arguments.
  scoped_array<char*> argv(new char *[arguments.size() + 1]);
  int total_args_size = 0;
  for (size_t i = 0; i < arguments.size(); ++i) {
    if (arguments[i] == NULL) {
      logger_->LogError("Bad parameter");
      return -1;
    }
    total_args_size += strlen(arguments[i]) + 1;
  }
  scoped_array<char> buffer(new char[total_args_size]);
  char *buffer_pointer = &buffer[0];

  for (size_t i = 0; i < arguments.size(); ++i) {
    argv[i] = buffer_pointer;
    strcpy(buffer_pointer, arguments[i]);
    buffer_pointer += strlen(arguments[i]);
    *buffer_pointer = '\0';
    ++buffer_pointer;
  }
  argv[arguments.size()] = NULL;

  int pid = fork();
  if (pid < 0) {
    logger_->LogError("Fork failed: %d", errno);
    return -1;
  }

  if (pid == 0) {
    int output_handle = HANDLE_EINTR(
        open(output_file, O_CREAT | O_WRONLY | O_TRUNC | O_EXCL, 0666));
    if (output_handle < 0) {
      logger_->LogError("Could not create %s: %d", output_file, errno);
      // Avoid exit() to avoid atexit handlers from parent.
      _exit(127);
    }
    dup2(output_handle, 1);
    dup2(output_handle, 2);
    execv(argv[0], &argv[0]);
    logger_->LogError("Exec failed: %d", errno);
    _exit(127);
  }

  int status = 0;
  if (HANDLE_EINTR(waitpid(pid, &status, 0)) < 0) {
    logger_->LogError("Problem waiting for pid: %d", errno);
    return -1;
  }
  if (!WIFEXITED(status)) {
    logger_->LogError("Process did not exit normally: %d", status);
    return -1;
  }
  return WEXITSTATUS(status);
}

std::string CrashCollector::Sanitize(const std::string &name) {
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

bool CrashCollector::GetUserInfoFromName(const std::string &name,
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

bool CrashCollector::GetCreatedCrashDirectoryByEuid(uid_t euid,
                                                    FilePath *crash_directory,
                                                    bool *out_of_capacity) {
  uid_t default_user_id;
  gid_t default_user_group;

  if (out_of_capacity != NULL) *out_of_capacity = false;

  // For testing.
  if (forced_crash_directory_ != NULL) {
    *crash_directory = FilePath(forced_crash_directory_);
    return true;
  }

  if (!GetUserInfoFromName(kDefaultUserName,
                           &default_user_id,
                           &default_user_group)) {
    logger_->LogError("Could not find default user info");
    return false;
  }
  mode_t directory_mode;
  uid_t directory_owner;
  gid_t directory_group;
  *crash_directory =
      GetCrashDirectoryInfo(euid,
                            default_user_id,
                            default_user_group,
                            &directory_mode,
                            &directory_owner,
                            &directory_group);

  if (!file_util::PathExists(*crash_directory)) {
    // Create the spool directory with the appropriate mode (regardless of
    // umask) and ownership.
    mode_t old_mask = umask(0);
    if (mkdir(crash_directory->value().c_str(), directory_mode) < 0 ||
        chown(crash_directory->value().c_str(),
              directory_owner,
              directory_group) < 0) {
      logger_->LogError("Unable to create appropriate crash directory");
      return false;
    }
    umask(old_mask);
  }

  if (!file_util::PathExists(*crash_directory)) {
    logger_->LogError("Unable to create crash directory %s",
                      crash_directory->value().c_str());
    return false;
  }

  if (!CheckHasCapacity(*crash_directory)) {
    if (out_of_capacity != NULL) *out_of_capacity = true;
    return false;
  }

  return true;
}

// Return true if the given crash directory has not already reached
// maximum capacity.
bool CrashCollector::CheckHasCapacity(const FilePath &crash_directory) {
  DIR* dir = opendir(crash_directory.value().c_str());
  if (!dir) {
    return false;
  }
  struct dirent ent_buf;
  struct dirent* ent;
  bool full = false;
  std::set<std::string> basenames;
  while (readdir_r(dir, &ent_buf, &ent) == 0 && ent != NULL) {
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
      logger_->LogWarning(
          "Crash directory %s already full with %d pending reports",
          crash_directory.value().c_str(),
          kMaxCrashDirectorySize);
      full = true;
      break;
    }
  }
  closedir(dir);
  return !full;
}

bool CrashCollector::IsCommentLine(const std::string &line) {
  size_t found = line.find_first_not_of(" ");
  return found != std::string::npos && line[found] == '#';
}

bool CrashCollector::ReadKeyValueFile(
    const FilePath &path,
    const char separator,
    std::map<std::string, std::string> *dictionary) {
  std::string contents;
  if (!file_util::ReadFileToString(path, &contents)) {
    return false;
  }
  typedef std::vector<std::string> StringVector;
  StringVector lines;
  SplitString(contents, '\n', &lines);
  bool any_errors = false;
  for (StringVector::iterator line = lines.begin(); line != lines.end();
       ++line) {
    // Allow empty strings.
    if (line->empty())
      continue;
    // Allow comment lines.
    if (IsCommentLine(*line))
      continue;
    StringVector sides;
    SplitString(*line, separator, &sides);
    if (sides.size() != 2) {
      any_errors = true;
      continue;
    }
    dictionary->insert(std::pair<std::string, std::string>(sides[0], sides[1]));
  }
  return !any_errors;
}

bool CrashCollector::GetLogContents(const FilePath &config_path,
                                    const std::string &exec_name,
                                    const FilePath &output_file) {
  std::map<std::string, std::string> log_commands;
  if (!ReadKeyValueFile(config_path, ':', &log_commands)) {
    logger_->LogInfo("Unable to read log configuration file %s",
                     config_path.value().c_str());
    return false;
  }

  if (log_commands.find(exec_name) == log_commands.end())
    return false;

  std::vector<const char *> command;
  command.push_back(kShellPath);
  command.push_back("-c");
  std::string shell_command = log_commands[exec_name];
  command.push_back(shell_command.c_str());

  int fork_result = ForkExecAndPipe(command, output_file.value().c_str());
  if (fork_result != 0) {
    logger_->LogInfo("Running shell command %s failed with: %d",
                     shell_command.c_str(), fork_result);
    return false;
  }
  return true;
}

void CrashCollector::AddCrashMetaData(const std::string &key,
                                      const std::string &value) {
  extra_metadata_.append(StringPrintf("%s=%s\n", key.c_str(), value.c_str()));
}

void CrashCollector::WriteCrashMetaData(const FilePath &meta_path,
                                        const std::string &exec_name,
                                        const std::string &payload_path) {
  std::map<std::string, std::string> contents;
  if (!ReadKeyValueFile(FilePath(std::string(lsb_release_)), '=', &contents)) {
    logger_->LogError("Problem parsing %s", lsb_release_);
    // Even though there was some failure, take as much as we could read.
  }
  std::string version("unknown");
  std::map<std::string, std::string>::iterator i;
  if ((i = contents.find("CHROMEOS_RELEASE_VERSION")) != contents.end()) {
    version = i->second;
  }
  int64 payload_size = -1;
  file_util::GetFileSize(FilePath(payload_path), &payload_size);
  std::string meta_data = StringPrintf("%sexec_name=%s\n"
                                       "ver=%s\n"
                                       "payload=%s\n"
                                       "payload_size=%lld\n"
                                       "done=1\n",
                                       extra_metadata_.c_str(),
                                       exec_name.c_str(),
                                       version.c_str(),
                                       payload_path.c_str(),
                                       payload_size);
  // We must use WriteNewFile instead of file_util::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(meta_path, meta_data.c_str(), meta_data.size()) < 0) {
    logger_->LogError("Unable to write %s", meta_path.value().c_str());
  }
}

bool CrashCollector::IsCrashTestInProgress() {
  return file_util::PathExists(FilePath(kCrashTestInProgressPath));
}
