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
#include <chromeos/flag_helper.h>
#include <chromeos/syslog_logging.h>

#include "constants.h"
#include "metrics_daemon.h"

const char kScalingMaxFreqPath[] =
    "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq";
const char kCpuinfoMaxFreqPath[] =
    "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";

int main(int argc, char** argv) {
  DEFINE_bool(daemon, true, "run as daemon (use -nodaemon for debugging)");

  // The uploader is disabled by default on ChromeOS as Chrome is responsible
  // for sending the metrics.
  DEFINE_bool(uploader, false, "activate the uploader");

  // Upload the metrics once and exit. (used for testing)
  DEFINE_bool(uploader_test,
              false,
              "run the uploader once and exit");

  // Enable dbus.
  DEFINE_bool(withdbus, true, "Enable dbus");

  // Upload Service flags.
  DEFINE_int32(upload_interval_secs,
               1800,
               "Interval at which metrics_daemon sends the metrics. (needs "
               "-uploader)");
  DEFINE_string(server,
                metrics::kMetricsServer,
                "Server to upload the metrics to. (needs -uploader)");
  DEFINE_string(metrics_file,
                metrics::kMetricsEventsFilePath,
                "File to use as a proxy for uploading the metrics");
  DEFINE_string(config_root,
                "/", "Root of the configuration files (testing only)");

  chromeos::FlagHelper::Init(argc, argv, "Chromium OS Metrics Daemon");

  // Also log to stderr when not running as daemon.
  chromeos::InitLog(chromeos::kLogToSyslog | chromeos::kLogHeader |
                    (FLAGS_daemon ? 0 : chromeos::kLogToStderr));

  if (FLAGS_daemon && daemon(0, 0) != 0) {
    return errno;
  }

  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  MetricsDaemon daemon;
  daemon.Init(FLAGS_uploader_test,
              FLAGS_uploader | FLAGS_uploader_test,
              FLAGS_withdbus,
              &metrics_lib,
              kScalingMaxFreqPath,
              kCpuinfoMaxFreqPath,
              base::TimeDelta::FromSeconds(FLAGS_upload_interval_secs),
              FLAGS_server,
              FLAGS_metrics_file,
              FLAGS_config_root);

  if (FLAGS_uploader_test) {
    daemon.RunUploaderTest();
    return 0;
  }

  daemon.Run();
}
