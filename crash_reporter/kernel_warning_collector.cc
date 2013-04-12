// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_warning_collector.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_number_conversions.h"
#include "base/string_util.h"
#include "base/stringprintf.h"

namespace {
const char kExecName[] = "kernel-warning";
const char kKernelWarningSignatureKey[] = "sig";
const char kKernelWarningPath[] = "/var/run/kwarn/warning";
const pid_t kKernelPid = 0;
const uid_t kRootUid = 0;
}  // namespace

KernelWarningCollector::KernelWarningCollector() {
}

KernelWarningCollector::~KernelWarningCollector() {
}

bool KernelWarningCollector::LoadKernelWarning(std::string *content,
                                               std::string *hash_string) {
  FilePath kernel_warning_path(kKernelWarningPath);
  if (!file_util::ReadFileToString(kernel_warning_path, content)) {
    LOG(ERROR) << "Could not open " << kKernelWarningPath;
    return false;
  }
  /* Verify that the first line contains an 8-digit hex hash. */
  *hash_string = content->substr(0, 8);
  std::vector<uint8> output;
  if (!base::HexStringToBytes(*hash_string, &output)) {
    LOG(ERROR) << "Bad hash " << *hash_string << " in " << kKernelWarningPath;
    return false;
  }
  return true;
}

bool KernelWarningCollector::Collect() {
  std::string reason = "normal collection";
  bool feedback = true;
  if (IsDeveloperImage()) {
    reason = "always collect from developer builds";
    feedback = true;
  } else if (!is_feedback_allowed_function_()) {
    reason = "no user consent";
    feedback = false;
  }

  LOG(INFO) << "Processing kernel warning: " << reason;

  if (!feedback) {
    return true;
  }

  std::string kernel_warning;
  std::string warning_hash;
  if (!LoadKernelWarning(&kernel_warning, &warning_hash)) {
    return true;
  }

  FilePath root_crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(kRootUid, &root_crash_directory, NULL)) {
    return true;
  }

  std::string dump_basename =
      FormatDumpBasename(kExecName, time(NULL), kKernelPid);
  FilePath kernel_crash_path = root_crash_directory.Append(
      StringPrintf("%s.kcrash", dump_basename.c_str()));

  // We must use WriteNewFile instead of file_util::WriteFile as we
  // do not want to write with root access to a symlink that an attacker
  // might have created.
  if (WriteNewFile(kernel_crash_path,
                   kernel_warning.data(),
                   kernel_warning.length()) !=
      static_cast<int>(kernel_warning.length())) {
    LOG(INFO) << "Failed to write kernel warning to "
              << kernel_crash_path.value().c_str();
    return true;
  }

  AddCrashMetaData(kKernelWarningSignatureKey, warning_hash);
  WriteCrashMetaData(
      root_crash_directory.Append(
          StringPrintf("%s.meta", dump_basename.c_str())),
    kExecName, kernel_crash_path.value());

  LOG(INFO) << "Stored kernel warning into " << kernel_crash_path.value();
  return true;
}
