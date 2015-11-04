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

#ifndef METRICSD_COLLECTORS_CPU_USAGE_COLLECTOR_H_
#define METRICSD_COLLECTORS_CPU_USAGE_COLLECTOR_H_

#include <base/time/time.h>

#include "metrics/metrics_library.h"

class CpuUsageCollector {
 public:
  CpuUsageCollector(MetricsLibraryInterface* metrics_library);

  // Initialize this collector's state.
  void Init();

  // Schedule a collection interval.
  void Schedule();

  // Callback called at the end of the collection interval.
  void CollectCallback();

  // Measure the cpu use and report it.
  void Collect();

  // Gets the current cumulated Cpu usage.
  base::TimeDelta GetCumulativeCpuUse();

 private:
  FRIEND_TEST(CpuUsageTest, ParseProcStat);
  bool ParseProcStat(const std::string& stat_content,
                     uint64_t *user_ticks,
                     uint64_t *user_nice_ticks,
                     uint64_t *system_ticks);

  int num_cpu_;
  uint32_t ticks_per_second_;

  base::TimeDelta collect_interval_;
  base::TimeDelta latest_cpu_use_;

  MetricsLibraryInterface* metrics_lib_;
};

#endif  // METRICSD_COLLECTORS_CPU_USAGE_COLLECTOR_H_
