/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>
#include <rootdev.h>

#include "constants.h"
#include "metrics_collector.h"


// Returns the path to the disk stats in the sysfs.  Returns the null string if
// it cannot find the disk stats file.
static
const std::string MetricsMainDiskStatsPath() {
  char dev_path_cstr[PATH_MAX];
  std::string dev_prefix = "/dev/block/";
  std::string dev_path;

  int ret = rootdev(dev_path_cstr, sizeof(dev_path_cstr), true, true);
  if (ret != 0) {
    LOG(WARNING) << "error " << ret << " determining root device";
    return "";
  }
  dev_path = dev_path_cstr;
  // Check that rootdev begins with "/dev/block/".
  if (!base::StartsWith(dev_path, dev_prefix,
                        base::CompareCase::INSENSITIVE_ASCII)) {
    LOG(WARNING) << "unexpected root device " << dev_path;
    return "";
  }
  return "/sys/class/block/" + dev_path.substr(dev_prefix.length()) + "/stat";
}

int main(int argc, char** argv) {
  DEFINE_bool(foreground, false, "Don't daemonize");

  DEFINE_string(private_directory, metrics::kMetricsCollectorDirectory,
                "Path to the private directory used by metrics_collector "
                "(testing only)");
  DEFINE_string(shared_directory, metrics::kSharedMetricsDirectory,
                "Path to the shared metrics directory, used by "
                "metrics_collector, metricsd and all metrics clients "
                "(testing only)");

  DEFINE_bool(logtostderr, false, "Log to standard error");
  DEFINE_bool(logtosyslog, false, "Log to syslog");

  brillo::FlagHelper::Init(argc, argv, "Chromium OS Metrics Daemon");

  int logging_location = (FLAGS_foreground ? brillo::kLogToStderr
                          : brillo::kLogToSyslog);
  if (FLAGS_logtosyslog)
    logging_location = brillo::kLogToSyslog;

  if (FLAGS_logtostderr)
    logging_location = brillo::kLogToStderr;

  // Also log to stderr when not running as daemon.
  brillo::InitLog(logging_location | brillo::kLogHeader);

  if (FLAGS_logtostderr && FLAGS_logtosyslog) {
    LOG(ERROR) << "only one of --logtosyslog and --logtostderr can be set";
    return 1;
  }

  if (!FLAGS_foreground && daemon(0, 0) != 0) {
    return errno;
  }

  MetricsLibrary metrics_lib;
  metrics_lib.InitWithNoCaching();
  MetricsCollector daemon;
  daemon.Init(false,
              &metrics_lib,
              MetricsMainDiskStatsPath(),
              base::FilePath(FLAGS_private_directory),
              base::FilePath(FLAGS_shared_directory));

  daemon.Run();
}
