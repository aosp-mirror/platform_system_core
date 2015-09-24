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

#include "collectors/disk_usage_collector.h"

#include <base/bind.h>
#include <base/bind_helpers.h>
#include <base/message_loop/message_loop.h>
#include <sys/statvfs.h>

#include "metrics/metrics_library.h"

namespace {

const char kDiskUsageMB[] = "Platform.DataPartitionUsed.MB";
const char kDiskUsagePercent[] = "Platform.DataPartitionUsed.Percent";
const char kDataPartitionPath[] = "/data";

// Collect every 15 minutes.
const int kDiskUsageCollectorIntervalSeconds = 900;

}  // namespace

DiskUsageCollector::DiskUsageCollector(
    MetricsLibraryInterface* metrics_library) {
  collect_interval_ = base::TimeDelta::FromSeconds(
      kDiskUsageCollectorIntervalSeconds);
  CHECK(metrics_library);
  metrics_lib_ = metrics_library;
}

void DiskUsageCollector::Collect() {
  struct statvfs buf;
  int result = statvfs(kDataPartitionPath, &buf);
  if (result != 0) {
    PLOG(ERROR) << "Failed to check the available space in "
                << kDataPartitionPath;
    return;
  }

  unsigned long total_space = buf.f_blocks * buf.f_bsize;
  unsigned long used_space = (buf.f_blocks - buf.f_bfree) * buf.f_bsize;
  int percent_used = (used_space * 100) / total_space;

  metrics_lib_->SendToUMA(kDiskUsageMB,
                          used_space / (1024 * 1024),
                          0,
                          1024, // up to 1 GB.
                          100);
  metrics_lib_->SendEnumToUMA(kDiskUsagePercent, percent_used, 101);
}

void DiskUsageCollector::CollectCallback() {
  Collect();
  Schedule();
}

void DiskUsageCollector::Schedule() {
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&DiskUsageCollector::CollectCallback, base::Unretained(this)),
      collect_interval_);
}
