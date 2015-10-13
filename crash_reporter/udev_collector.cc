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

#include "udev_collector.h"

#include <map>
#include <utility>
#include <vector>

#include <base/files/file_enumerator.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/process.h>

using base::FilePath;

namespace {

const char kCollectUdevSignature[] = "crash_reporter-udev-collection";
const char kGzipPath[] = "/bin/gzip";
const char kUdevExecName[] = "udev";
const char kUdevSignatureKey[] = "sig";
const char kUdevSubsystemDevCoredump[] = "devcoredump";
const char kDefaultDevCoredumpDirectory[] = "/sys/class/devcoredump";
const char kDevCoredumpFilePrefixFormat[] = "devcoredump_%s";

}  // namespace

UdevCollector::UdevCollector()
    : dev_coredump_directory_(kDefaultDevCoredumpDirectory) {}

UdevCollector::~UdevCollector() {}

bool UdevCollector::HandleCrash(const std::string &udev_event) {
  if (IsDeveloperImage()) {
    LOG(INFO) << "developer image - collect udev crash info.";
  } else if (is_feedback_allowed_function_()) {
    LOG(INFO) << "Consent given - collect udev crash info.";
  } else {
    LOG(INFO) << "Ignoring - Non-developer image and no consent given.";
    return false;
  }

  // Process the udev event string.
  // First get all the key-value pairs.
  std::vector<std::pair<std::string, std::string>> udev_event_keyval;
  base::SplitStringIntoKeyValuePairs(udev_event, '=', ':', &udev_event_keyval);
  std::vector<std::pair<std::string, std::string>>::const_iterator iter;
  std::map<std::string, std::string> udev_event_map;
  for (iter = udev_event_keyval.begin();
       iter != udev_event_keyval.end();
       ++iter) {
    udev_event_map[iter->first] = iter->second;
  }

  // Make sure the crash directory exists, or create it if it doesn't.
  FilePath crash_directory;
  if (!GetCreatedCrashDirectoryByEuid(0, &crash_directory, nullptr)) {
    LOG(ERROR) << "Could not get crash directory.";
    return false;
  }

  if (udev_event_map["SUBSYSTEM"] == kUdevSubsystemDevCoredump) {
    int instance_number;
    if (!base::StringToInt(udev_event_map["KERNEL_NUMBER"], &instance_number)) {
      LOG(ERROR) << "Invalid kernel number: "
                 << udev_event_map["KERNEL_NUMBER"];
      return false;
    }
    return ProcessDevCoredump(crash_directory, instance_number);
  }

  return ProcessUdevCrashLogs(crash_directory,
                              udev_event_map["ACTION"],
                              udev_event_map["KERNEL"],
                              udev_event_map["SUBSYSTEM"]);
}

bool UdevCollector::ProcessUdevCrashLogs(const FilePath& crash_directory,
                                         const std::string& action,
                                         const std::string& kernel,
                                         const std::string& subsystem) {
  // Construct the basename string for crash_reporter_logs.conf:
  //   "crash_reporter-udev-collection-[action]-[name]-[subsystem]"
  // If a udev field is not provided, "" is used in its place, e.g.:
  //   "crash_reporter-udev-collection-[action]--[subsystem]"
  // Hence, "" is used as a wildcard name string.
  // TODO(sque, crosbug.com/32238): Implement wildcard checking.
  std::string basename = action + "-" + kernel + "-" + subsystem;
  std::string udev_log_name = std::string(kCollectUdevSignature) + '-' +
                              basename;

  // Create the destination path.
  std::string log_file_name =
      FormatDumpBasename(basename, time(nullptr), 0);
  FilePath crash_path = GetCrashPath(crash_directory, log_file_name, "log");

  // Handle the crash.
  bool result = GetLogContents(log_config_path_, udev_log_name, crash_path);
  if (!result) {
    LOG(ERROR) << "Error reading udev log info " << udev_log_name;
    return false;
  }

  // Compress the output using gzip.
  brillo::ProcessImpl gzip_process;
  gzip_process.AddArg(kGzipPath);
  gzip_process.AddArg(crash_path.value());
  int process_result = gzip_process.Run();
  FilePath crash_path_zipped = FilePath(crash_path.value() + ".gz");
  // If the zip file was not created, use the uncompressed file.
  if (process_result != 0 || !base::PathExists(crash_path_zipped))
    LOG(ERROR) << "Could not create zip file " << crash_path_zipped.value();
  else
    crash_path = crash_path_zipped;

  std::string exec_name = std::string(kUdevExecName) + "-" + subsystem;
  AddCrashMetaData(kUdevSignatureKey, udev_log_name);
  WriteCrashMetaData(GetCrashPath(crash_directory, log_file_name, "meta"),
                     exec_name, crash_path.value());
  return true;
}

bool UdevCollector::ProcessDevCoredump(const FilePath& crash_directory,
                                       int instance_number) {
  FilePath coredump_path =
      FilePath(base::StringPrintf("%s/devcd%d/data",
                                  dev_coredump_directory_.c_str(),
                                  instance_number));
  if (!base::PathExists(coredump_path)) {
    LOG(ERROR) << "Device coredump file " << coredump_path.value()
               << " does not exist";
    return false;
  }

  // Add coredump file to the crash directory.
  if (!AppendDevCoredump(crash_directory, coredump_path, instance_number)) {
    ClearDevCoredump(coredump_path);
    return false;
  }

  // Clear the coredump data to allow generation of future device coredumps
  // without having to wait for the 5-minutes timeout.
  return ClearDevCoredump(coredump_path);
}

bool UdevCollector::AppendDevCoredump(const FilePath& crash_directory,
                                      const FilePath& coredump_path,
                                      int instance_number) {
  // Retrieve the driver name of the failing device.
  std::string driver_name = GetFailingDeviceDriverName(instance_number);
  if (driver_name.empty()) {
    LOG(ERROR) << "Failed to obtain driver name for instance: "
               << instance_number;
    return false;
  }

  std::string coredump_prefix =
      base::StringPrintf(kDevCoredumpFilePrefixFormat, driver_name.c_str());

  std::string dump_basename = FormatDumpBasename(coredump_prefix,
                                                 time(nullptr),
                                                 instance_number);
  FilePath core_path = GetCrashPath(crash_directory, dump_basename, "devcore");
  FilePath log_path = GetCrashPath(crash_directory, dump_basename, "log");
  FilePath meta_path = GetCrashPath(crash_directory, dump_basename, "meta");

  // Collect coredump data.
  if (!base::CopyFile(coredump_path, core_path)) {
    LOG(ERROR) << "Failed to copy device coredumpm file from "
               << coredump_path.value() << " to " << core_path.value();
    return false;
  }

  // Collect additional logs if one is specified in the config file.
  std::string udev_log_name = std::string(kCollectUdevSignature) + '-' +
      kUdevSubsystemDevCoredump + '-' + driver_name;
  bool result = GetLogContents(log_config_path_, udev_log_name, log_path);
  if (result) {
    AddCrashMetaUploadFile("logs", log_path.value());
  }

  WriteCrashMetaData(meta_path, coredump_prefix, core_path.value());

  return true;
}

bool UdevCollector::ClearDevCoredump(const FilePath& coredump_path) {
  if (!base::WriteFile(coredump_path, "0", 1)) {
    LOG(ERROR) << "Failed to delete the coredump data file "
               << coredump_path.value();
    return false;
  }
  return true;
}

std::string UdevCollector::GetFailingDeviceDriverName(int instance_number) {
  FilePath failing_uevent_path =
      FilePath(base::StringPrintf("%s/devcd%d/failing_device/uevent",
                                  dev_coredump_directory_.c_str(),
                                  instance_number));
  if (!base::PathExists(failing_uevent_path)) {
    LOG(ERROR) << "Failing uevent path " << failing_uevent_path.value()
               << " does not exist";
    return "";
  }

  std::string uevent_content;
  if (!base::ReadFileToString(failing_uevent_path, &uevent_content)) {
    LOG(ERROR) << "Failed to read uevent file " << failing_uevent_path.value();
    return "";
  }

  // Parse uevent file contents as key-value pairs.
  std::vector<std::pair<std::string, std::string>> uevent_keyval;
  base::SplitStringIntoKeyValuePairs(uevent_content, '=', '\n', &uevent_keyval);
  std::vector<std::pair<std::string, std::string>>::const_iterator iter;
  for (iter = uevent_keyval.begin();
       iter != uevent_keyval.end();
       ++iter) {
    if (iter->first == "DRIVER") {
      return iter->second;
    }
  }

  return "";
}
