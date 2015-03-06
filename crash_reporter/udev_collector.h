// Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRASH_REPORTER_UDEV_COLLECTOR_H_
#define CRASH_REPORTER_UDEV_COLLECTOR_H_

#include <string>

#include <base/files/file_path.h>
#include <base/macros.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "crash-reporter/crash_collector.h"

// Udev crash collector.
class UdevCollector : public CrashCollector {
 public:
  UdevCollector();

  ~UdevCollector() override;

  // The udev event string should be formatted as follows:
  //   "ACTION=[action]:KERNEL=[name]:SUBSYSTEM=[subsystem]"
  // The values don't have to be in any particular order. One or more of them
  // could be omitted, in which case it would be treated as a wildcard (*).
  bool HandleCrash(const std::string& udev_event);

 protected:
  std::string dev_coredump_directory_;

 private:
  friend class UdevCollectorTest;

  // Process udev crash logs, collecting log files according to the config
  // file (crash_reporter_logs.conf).
  bool ProcessUdevCrashLogs(const base::FilePath& crash_directory,
                            const std::string& action,
                            const std::string& kernel,
                            const std::string& subsystem);
  // Process device coredump, collecting device coredump file.
  // |instance_number| is the kernel number of the virtual device for the device
  // coredump instance.
  bool ProcessDevCoredump(const base::FilePath& crash_directory,
                          int instance_number);
  // Copy device coredump file to crash directory, and perform necessary
  // coredump file management.
  bool AppendDevCoredump(const base::FilePath& crash_directory,
                         const base::FilePath& coredump_path,
                         int instance_number);
  // Clear the device coredump file by performing a dummy write to it.
  bool ClearDevCoredump(const base::FilePath& coredump_path);
  // Return the driver name of the device that generates the coredump.
  std::string GetFailingDeviceDriverName(int instance_number);

  // Mutator for unit testing.
  void set_log_config_path(const std::string& path) {
    log_config_path_ = base::FilePath(path);
  }

  DISALLOW_COPY_AND_ASSIGN(UdevCollector);
};

#endif  // CRASH_REPORTER_UDEV_COLLECTOR_H_
