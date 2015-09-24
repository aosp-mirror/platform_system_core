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

#ifndef METRICSD_COLLECTORS_DISK_USAGE_COLLECTOR_H_
#define METRICSD_COLLECTORS_DISK_USAGE_COLLECTOR_H_

#include <base/time/time.h>

#include "metrics/metrics_library.h"

class DiskUsageCollector {
 public:
  DiskUsageCollector(MetricsLibraryInterface* metrics_library);

  // Schedule the next collection.
  void Schedule();

  // Callback used by the main loop.
  void CollectCallback();

  // Collect the disk usage statistics and report them.
  void Collect();

 private:
  base::TimeDelta collect_interval_;
  MetricsLibraryInterface* metrics_lib_;
};

#endif  // METRICSD_COLLECTORS_DISK_USAGE_COLLECTOR_H_
