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

#ifndef METRICSD_COLLECTORS_AVERAGED_STATISTICS_COLLECTOR_H_
#define METRICSD_COLLECTORS_AVERAGED_STATISTICS_COLLECTOR_H_

#include "metrics/metrics_library.h"

class AveragedStatisticsCollector {
 public:
  AveragedStatisticsCollector(MetricsLibraryInterface* metrics_library,
                              const std::string& diskstats_path,
                              const std::string& vmstat_path);

  // Schedule a wait period.
  void ScheduleWait();

  // Schedule a collection period.
  void ScheduleCollect();

  // Callback used by the main loop.
  void CollectCallback();

  // Callback used by the main loop.
  void WaitCallback();

  // Read and store the initial values at the beginning of a collection cycle.
  void ReadInitialValues();

  // Collect the disk usage statistics and report them.
  void Collect();

 private:
  friend class AveragedStatisticsTest;
  FRIEND_TEST(AveragedStatisticsTest, ParseDiskStats);
  FRIEND_TEST(AveragedStatisticsTest, ParseVmStats);

  // Record for retrieving and reporting values from /proc/vmstat
  struct VmstatRecord {
    uint64_t page_faults;    // major faults
    uint64_t swap_in;        // pages swapped in
    uint64_t swap_out;       // pages swapped out
  };

  // Read the disk read/write statistics for the main disk.
  bool DiskStatsReadStats(uint64_t* read_sectors, uint64_t* write_sectors);

  // Parse the content of the vmstats file into |record|.
  bool VmStatsParseStats(const char* stats, struct VmstatRecord* record);

  // Read the vmstats into |stats|.
  bool VmStatsReadStats(struct VmstatRecord* stats);

  MetricsLibraryInterface* metrics_lib_;
  base::FilePath diskstats_path_;
  base::FilePath vmstats_path_;

  // Values observed at the beginning of the collection period.
  uint64_t read_sectors_;
  uint64_t write_sectors_;
  struct VmstatRecord vmstats_;

  double stats_start_time_;
};

#endif  // METRICSD_COLLECTORS_AVERAGED_STATISTICS_COLLECTOR_H_
