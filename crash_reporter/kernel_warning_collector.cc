// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_warning_collector.h"

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>

namespace {
const char kExecName[] = "kernel-warning";
const char kKernelWarningSignatureKey[] = "sig";
const char kKernelWarningPath[] = "/var/run/kwarn/warning";
const pid_t kKernelPid = 0;
const uid_t kRootUid = 0;
}  // namespace

using base::FilePath;
using base::StringPrintf;

KernelWarningCollector::KernelWarningCollector() {
}

KernelWarningCollector::~KernelWarningCollector() {
}

bool KernelWarningCollector::LoadKernelWarning(std::string *content,
                                               std::string *signature) {
  FilePath kernel_warning_path(kKernelWarningPath);
  if (!base::ReadFileToString(kernel_warning_path, content)) {
    LOG(ERROR) << "Could not open " << kKernelWarningPath;
    return false;
  }
  // The signature is in the first line.
  std::string::size_type end_position = content->find('\n');
  if (end_position == std::string::npos) {
    LOG(ERROR) << "unexpected kernel warning format";
    return false;
  }
  *signature = content->substr(0, end_position);
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
  std::string warning_signature;
  if (!LoadKernelWarning(&kernel_warning, &warning_signature)) {
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

  // We must use WriteNewFile instead of base::WriteFile as we
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

  AddCrashMetaData(kKernelWarningSignatureKey, warning_signature);
  WriteCrashMetaData(
      root_crash_directory.Append(
          StringPrintf("%s.meta", dump_basename.c_str())),
    kExecName, kernel_crash_path.value());

  LOG(INFO) << "Stored kernel warning into " << kernel_crash_path.value();
  return true;
}
