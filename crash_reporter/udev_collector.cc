// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crash-reporter/udev_collector.h"

#include <map>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <chromeos/process.h>

static const char kCollectUdevSignature[] = "crash_reporter-udev-collection";
static const char kGzipPath[] = "/bin/gzip";
static const char kUdevExecName[] = "udev";
static const char kUdevSignatureKey[] = "sig";

using base::FilePath;

UdevCollector::UdevCollector() {}

UdevCollector::~UdevCollector() {}

bool UdevCollector::HandleCrash(const std::string &udev_event) {
  if (!is_feedback_allowed_function_()) {
    LOG(ERROR) << "No consent given to collect crash info.";
    return false;
  }

  // Process the udev event string.
  // First get all the key-value pairs.
  std::vector<std::pair<std::string, std::string> > udev_event_keyval;
  base::SplitStringIntoKeyValuePairs(udev_event, '=', ':', &udev_event_keyval);
  std::vector<std::pair<std::string, std::string> >::const_iterator iter;
  std::map<std::string, std::string> udev_event_map;
  for (iter = udev_event_keyval.begin();
       iter != udev_event_keyval.end();
       ++iter) {
    udev_event_map[iter->first] = iter->second;
  }

  // Construct the basename string for crash_reporter_logs.conf:
  //   "crash_reporter-udev-collection-[action]-[name]-[subsystem]"
  // If a udev field is not provided, "" is used in its place, e.g.:
  //   "crash_reporter-udev-collection-[action]--[subsystem]"
  // Hence, "" is used as a wildcard name string.
  // TODO(sque, crosbug.com/32238): Implement wildcard checking.
  std::string basename = udev_event_map["ACTION"] + "-" +
                         udev_event_map["KERNEL"] + "-" +
                         udev_event_map["SUBSYSTEM"];
  std::string udev_log_name = std::string(kCollectUdevSignature) + '-' +
                              basename;

  // Make sure the crash directory exists, or create it if it doesn't.
  FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(0, &crash_directory, NULL)) {
    LOG(ERROR) << "Could not get crash directory.";
    return false;
  }
  // Create the destination path.
  std::string log_file_name =
      FormatDumpBasename(basename, time(NULL), 0);
  FilePath crash_path = GetCrashPath(crash_directory, log_file_name, "log");

  // Handle the crash.
  bool result = GetLogContents(log_config_path_, udev_log_name, crash_path);
  if (!result) {
    LOG(ERROR) << "Error reading udev log info " << udev_log_name;
    return false;
  }

  // Compress the output using gzip.
  chromeos::ProcessImpl gzip_process;
  gzip_process.AddArg(kGzipPath);
  gzip_process.AddArg(crash_path.value());
  int process_result = gzip_process.Run();
  FilePath crash_path_zipped = FilePath(crash_path.value() + ".gz");
  // If the zip file was not created, use the uncompressed file.
  if (process_result != 0 || !base::PathExists(crash_path_zipped))
    LOG(ERROR) << "Could not create zip file " << crash_path_zipped.value();
  else
    crash_path = crash_path_zipped;

  std::string exec_name = std::string(kUdevExecName) + "-" +
      udev_event_map["SUBSYSTEM"];
  AddCrashMetaData(kUdevSignatureKey, udev_log_name);
  WriteCrashMetaData(GetCrashPath(crash_directory, log_file_name, "meta"),
                     exec_name, crash_path.value());
  return true;
}
