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

#include <base/command_line.h>
#include <base/files/file_path.h>
#include <base/logging.h>
#include <base/time/time.h>
#include <brillo/flag_helper.h>
#include <brillo/syslog_logging.h>

#include "constants.h"
#include "uploader/metricsd_service_runner.h"
#include "uploader/upload_service.h"

int main(int argc, char** argv) {
  DEFINE_bool(foreground, false, "Don't daemonize");

  // Upload the metrics once and exit. (used for testing)
  DEFINE_bool(uploader_test, false, "run the uploader once and exit");

  // Upload Service flags.
  DEFINE_int32(upload_interval_secs, 1800,
               "Interval at which metricsd uploads the metrics.");
  DEFINE_int32(disk_persistence_interval_secs, 300,
               "Interval at which metricsd saves the aggregated metrics to "
               "disk to avoid losing them if metricsd stops in between "
               "two uploads.");
  DEFINE_string(server, metrics::kMetricsServer,
                "Server to upload the metrics to.");
  DEFINE_string(private_directory, metrics::kMetricsdDirectory,
                "Path to the private directory used by metricsd "
                "(testing only)");
  DEFINE_string(shared_directory, metrics::kSharedMetricsDirectory,
                "Path to the shared metrics directory, used by "
                "metrics_collector, metricsd and all metrics clients "
                "(testing only)");

  DEFINE_bool(logtostderr, false, "Log to standard error");
  DEFINE_bool(logtosyslog, false, "Log to syslog");

  brillo::FlagHelper::Init(argc, argv, "Brillo metrics daemon.");

  int logging_location =
      (FLAGS_foreground ? brillo::kLogToStderr : brillo::kLogToSyslog);
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

  UploadService upload_service(
      FLAGS_server, base::TimeDelta::FromSeconds(FLAGS_upload_interval_secs),
      base::TimeDelta::FromSeconds(FLAGS_disk_persistence_interval_secs),
      base::FilePath(FLAGS_private_directory),
      base::FilePath(FLAGS_shared_directory));

  return upload_service.Run();
}
