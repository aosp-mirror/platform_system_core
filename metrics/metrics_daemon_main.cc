// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#include <gflags/gflags.h>

#include "metrics_daemon.h"

DEFINE_bool(daemon, true, "run as daemon (use -nodaemon for debugging)");

// Path to disk stats.  This may be system dependent.
const char kMetricsMainDiskStatsPath[] = "/sys/class/block/sda/stat";

int main(int argc, char** argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  MetricsLibrary metrics_lib;
  metrics_lib.Init();
  MetricsDaemon daemon;
  daemon.Init(false, &metrics_lib, kMetricsMainDiskStatsPath);
  daemon.Run(FLAGS_daemon);
}
