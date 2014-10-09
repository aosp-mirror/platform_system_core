// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_util.h>
#include <chromeos/flag_helper.h>
#include <chromeos/syslog_logging.h>
#include <rootdev/rootdev.h>

#include "metrics/metrics_daemon.h"

const char kScalingMaxFreqPath[] =
    "/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq";
const char kCpuinfoMaxFreqPath[] =
    "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq";

// Returns the path to the disk stats in the sysfs.  Returns the null string if
// it cannot find the disk stats file.
static
const std::string MetricsMainDiskStatsPath() {
  char dev_path_cstr[PATH_MAX];
  std::string dev_prefix = "/dev/";
  std::string dev_path;
  std::string dev_name;

  int ret = rootdev(dev_path_cstr, sizeof(dev_path_cstr), true, true);
  if (ret != 0) {
    LOG(WARNING) << "error " << ret << " determining root device";
    return "";
  }
  dev_path = dev_path_cstr;
  // Check that rootdev begins with "/dev/".
  if (!StartsWithASCII(dev_path, dev_prefix, false)) {
    LOG(WARNING) << "unexpected root device " << dev_path;
    return "";
  }
  // Get the device name, e.g. "sda" from "/dev/sda".
  dev_name = dev_path.substr(dev_prefix.length());
  return "/sys/class/block/" + dev_name + "/stat";
}

int main(int argc, char** argv) {
  DEFINE_bool(daemon, true, "run as daemon (use -nodaemon for debugging)");

  // The uploader is disabled by default on ChromeOS as Chrome is responsible
  // for sending the metrics.
  DEFINE_bool(uploader, false, "activate the uploader");

  // Upload the metrics once and exit. (used for testing)
  DEFINE_bool(uploader_test,
              false,
              "run the uploader once and exit");

  // Upload Service flags.
  DEFINE_int32(upload_interval_secs,
               1800,
               "Interval at which metrics_daemon sends the metrics. (needs "
               "-uploader)");
  DEFINE_string(server,
                "https://clients4.google.com/uma/v2",
                "Server to upload the metrics to. (needs -uploader)");
  DEFINE_string(metrics_file,
                "/var/run/metrics/uma-events",
                "File to use as a proxy for uploading the metrics");
  DEFINE_string(config_root,
                "/", "Root of the configuration files (testing only)");

  chromeos::FlagHelper::Init(argc, argv, "Chromium OS Metrics Daemon");

  // Also log to stderr when not running as daemon.
  chromeos::InitLog(chromeos::kLogToSyslog | chromeos::kLogHeader |
                    (FLAGS_daemon ? 0 : chromeos::kLogToStderr));
  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  MetricsDaemon daemon;
  daemon.Init(FLAGS_uploader_test,
              FLAGS_uploader | FLAGS_uploader_test,
              &metrics_lib,
              MetricsMainDiskStatsPath(),
              "/proc/vmstat",
              kScalingMaxFreqPath,
              kCpuinfoMaxFreqPath,
              base::TimeDelta::FromSeconds(FLAGS_upload_interval_secs),
              FLAGS_server,
              FLAGS_metrics_file,
              FLAGS_config_root);


  base::AtExitManager at_exit_manager;
  if (FLAGS_uploader_test) {
    daemon.RunUploaderTest();
    return 0;
  }

  daemon.Run(FLAGS_daemon);
}
