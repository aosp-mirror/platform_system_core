// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/crash_collector.h"

#include <pwd.h>  // For struct passwd.
#include <sys/types.h>  // for mode_t.

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash-reporter/system_logging.h"

static const char kDefaultUserName[] = "chronos";
static const char kSystemCrashPath[] = "/var/spool/crash";
static const char kUserCrashPath[] = "/home/chronos/user/crash";

// Directory mode of the user crash spool directory.
static const mode_t kUserCrashPathMode = 0755;

// Directory mode of the system crash spool directory.
static const mode_t kSystemCrashPathMode = 01755;

static const uid_t kRootOwner = 0;
static const uid_t kRootGroup = 0;

CrashCollector::CrashCollector() : forced_crash_directory_(NULL) {
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

std::string CrashCollector::FormatDumpBasename(const std::string &exec_name,
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
                                                    FilePath *crash_directory) {
  uid_t default_user_id;
  gid_t default_user_group;

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

  return true;
}
