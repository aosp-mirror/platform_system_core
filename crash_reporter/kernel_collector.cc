// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/kernel_collector.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/string_util.h"
#include "crash-reporter/system_logging.h"

static const char kKernelExecName[] = "kernel";
static const char kPreservedDumpPath[] = "/sys/kernel/debug/preserved/kcrash";
const pid_t kKernelPid = 0;
const uid_t kRootUid = 0;

const char KernelCollector::kClearingSequence[] = " ";

KernelCollector::KernelCollector()
    : is_enabled_(false),
      preserved_dump_path_(kPreservedDumpPath) {
}

KernelCollector::~KernelCollector() {
}

void KernelCollector::OverridePreservedDumpPath(const FilePath &file_path) {
  preserved_dump_path_ = file_path;
}

bool KernelCollector::LoadPreservedDump(std::string *contents) {
  // clear contents since ReadFileToString actually appends to the string.
  contents->clear();
  if (!file_util::ReadFileToString(preserved_dump_path_, contents)) {
    logger_->LogError("Unable to read %s",
                      preserved_dump_path_.value().c_str());
    return false;
  }
  return true;
}

bool KernelCollector::Enable() {
  if (!file_util::PathExists(preserved_dump_path_)) {
    logger_->LogWarning("Kernel does not support crash dumping");
    return false;
  }

  // To enable crashes, we will eventually need to set
  // the chnv bit in BIOS, but it does not yet work.
  logger_->LogInfo("Enabling kernel crash handling");
  is_enabled_ = true;
  return true;
}

bool KernelCollector::ClearPreservedDump() {
  // It is necessary to write at least one byte to the kcrash file for
  // the log to actually be cleared.
  if (file_util::WriteFile(
          preserved_dump_path_,
          kClearingSequence,
          strlen(kClearingSequence)) != strlen(kClearingSequence)) {
    logger_->LogError("Failed to clear kernel crash dump");
    return false;
  }
  logger_->LogInfo("Cleared kernel crash diagnostics");
  return true;
}

bool KernelCollector::Collect() {
  std::string kernel_dump;
  FilePath root_crash_directory;
  if (!LoadPreservedDump(&kernel_dump)) {
    return false;
  }
  if (kernel_dump.empty()) {
    return false;
  }
  logger_->LogInfo("Received prior crash notification from kernel");

  if (is_feedback_allowed_function_()) {
    count_crash_function_();

    if (!GetCreatedCrashDirectoryByEuid(kRootUid,
                                        &root_crash_directory)) {
      return true;
    }

    std::string dump_basename =
        FormatDumpBasename(kKernelExecName,
                           time(NULL),
                           kKernelPid);
    FilePath kernel_crash_path = root_crash_directory.Append(
        StringPrintf("%s.kcrash", dump_basename.c_str()));

    if (file_util::WriteFile(kernel_crash_path,
                             kernel_dump.data(),
                             kernel_dump.length()) !=
        static_cast<int>(kernel_dump.length())) {
      logger_->LogInfo("Failed to write kernel dump to %s",
                       kernel_crash_path.value().c_str());
      return true;
    }

    WriteCrashMetaData(
        root_crash_directory.Append(
            StringPrintf("%s.meta", dump_basename.c_str())),
        kKernelExecName,
        kernel_crash_path.value());

    logger_->LogInfo("Collected kernel crash diagnostics into %s",
                     kernel_crash_path.value().c_str());
  } else {
    logger_->LogInfo("Crash not saved since metrics disabled");
  }
  if (!ClearPreservedDump()) {
    return false;
  }

  return true;
}
