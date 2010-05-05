// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.


#include <gflags/gflags.h>

#include "metrics_daemon.h"

DEFINE_bool(daemon, true, "run as daemon (use -nodaemon for debugging)");

int main(int argc, char** argv) {
  MetricsDaemon::MetricsDaemon d;
  google::ParseCommandLineFlags(&argc, &argv, true);
  d.Run(FLAGS_daemon);
}
