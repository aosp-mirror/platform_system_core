// Copyright (c) 2009 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_daemon.h"

int main(int argc, char** argv) {
  MetricsDaemon d;
  d.Run(false, true);
}
