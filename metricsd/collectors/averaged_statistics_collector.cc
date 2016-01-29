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

#include "averaged_statistics_collector.h"

#include <base/bind.h>
#include <base/files/file_util.h>
#include <base/files/file_path.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>

#include "metrics_collector.h"

namespace {

// disk stats metrics

// The {Read,Write}Sectors numbers are in sectors/second.
// A sector is usually 512 bytes.
const char kReadSectorsHistogramName[] = "Platform.ReadSectors";
const char kWriteSectorsHistogramName[] = "Platform.WriteSectors";
const int kDiskMetricsStatItemCount = 11;

// Assume a max rate of 250Mb/s for reads (worse for writes) and 512 byte
// sectors.
const int kSectorsIOMax = 500000;  // sectors/second
const int kSectorsBuckets = 50;    // buckets

// Page size is 4k, sector size is 0.5k.  We're not interested in page fault
// rates that the disk cannot sustain.
const int kPageFaultsMax = kSectorsIOMax / 8;  // Page faults/second
const int kPageFaultsBuckets = 50;

// Major page faults, i.e. the ones that require data to be read from disk.
const char kPageFaultsHistogramName[] = "Platform.PageFaults";

// Swap in and Swap out
const char kSwapInHistogramName[] = "Platform.SwapIn";
const char kSwapOutHistogramName[] = "Platform.SwapOut";

const int kIntervalBetweenCollection = 60;  // seconds
const int kCollectionDuration = 1;  // seconds

}  // namespace

AveragedStatisticsCollector::AveragedStatisticsCollector(
    MetricsLibraryInterface* metrics_library,
    const std::string& diskstats_path,
    const std::string& vmstats_path) :
  metrics_lib_(metrics_library),
  diskstats_path_(diskstats_path),
  vmstats_path_(vmstats_path) {
}

void AveragedStatisticsCollector::ScheduleWait() {
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&AveragedStatisticsCollector::WaitCallback,
                 base::Unretained(this)),
      base::TimeDelta::FromSeconds(
          kIntervalBetweenCollection - kCollectionDuration));
}

void AveragedStatisticsCollector::ScheduleCollect() {
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&AveragedStatisticsCollector::CollectCallback,
                 base::Unretained(this)),
      base::TimeDelta::FromSeconds(kCollectionDuration));
}

void AveragedStatisticsCollector::WaitCallback() {
  ReadInitialValues();
  ScheduleCollect();
}

void AveragedStatisticsCollector::CollectCallback() {
  Collect();
  ScheduleWait();
}

void AveragedStatisticsCollector::ReadInitialValues() {
  stats_start_time_ = MetricsCollector::GetActiveTime();
  DiskStatsReadStats(&read_sectors_, &write_sectors_);
  VmStatsReadStats(&vmstats_);
}

bool AveragedStatisticsCollector::DiskStatsReadStats(
    uint64_t* read_sectors, uint64_t* write_sectors) {
  CHECK(read_sectors);
  CHECK(write_sectors);
  std::string line;
  if (diskstats_path_.empty()) {
    return false;
  }

  if (!base::ReadFileToString(base::FilePath(diskstats_path_), &line)) {
    PLOG(WARNING) << "Could not read disk stats from "
                  << diskstats_path_.value();
    return false;
  }

  std::vector<std::string> parts = base::SplitString(
      line, " ", base::TRIM_WHITESPACE, base::SPLIT_WANT_NONEMPTY);
  if (parts.size() != kDiskMetricsStatItemCount) {
    LOG(ERROR) << "Could not parse disk stat correctly. Expected "
               << kDiskMetricsStatItemCount << " elements but got "
               << parts.size();
    return false;
  }
  if (!base::StringToUint64(parts[2], read_sectors)) {
    LOG(ERROR) << "Couldn't convert read sectors " << parts[2] << " to uint64";
    return false;
  }
  if (!base::StringToUint64(parts[6], write_sectors)) {
    LOG(ERROR) << "Couldn't convert write sectors " << parts[6] << " to uint64";
    return false;
  }

  return true;
}

bool AveragedStatisticsCollector::VmStatsParseStats(
    const char* stats, struct VmstatRecord* record) {
  CHECK(stats);
  CHECK(record);
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(stats, ' ', '\n', &pairs);

  for (base::StringPairs::iterator it = pairs.begin();
       it != pairs.end(); ++it) {
    if (it->first == "pgmajfault" &&
        !base::StringToUint64(it->second, &record->page_faults)) {
      return false;
    }
    if (it->first == "pswpin" &&
        !base::StringToUint64(it->second, &record->swap_in)) {
      return false;
    }
    if (it->first == "pswpout" &&
        !base::StringToUint64(it->second, &record->swap_out)) {
      return false;
    }
  }
  return true;
}

bool AveragedStatisticsCollector::VmStatsReadStats(struct VmstatRecord* stats) {
  CHECK(stats);
  std::string value_string;
  if (!base::ReadFileToString(vmstats_path_, &value_string)) {
    LOG(WARNING) << "cannot read " << vmstats_path_.value();
    return false;
  }
  return VmStatsParseStats(value_string.c_str(), stats);
}

void AveragedStatisticsCollector::Collect() {
  uint64_t read_sectors_now, write_sectors_now;
  struct VmstatRecord vmstats_now;
  double time_now = MetricsCollector::GetActiveTime();
  double delta_time = time_now - stats_start_time_;
  bool diskstats_success = DiskStatsReadStats(&read_sectors_now,
                                              &write_sectors_now);

  int delta_read = read_sectors_now - read_sectors_;
  int delta_write = write_sectors_now - write_sectors_;
  int read_sectors_per_second = delta_read / delta_time;
  int write_sectors_per_second = delta_write / delta_time;
  bool vmstats_success = VmStatsReadStats(&vmstats_now);
  uint64_t delta_faults = vmstats_now.page_faults - vmstats_.page_faults;
  uint64_t delta_swap_in = vmstats_now.swap_in - vmstats_.swap_in;
  uint64_t delta_swap_out = vmstats_now.swap_out - vmstats_.swap_out;
  uint64_t page_faults_per_second = delta_faults / delta_time;
  uint64_t swap_in_per_second = delta_swap_in / delta_time;
  uint64_t swap_out_per_second = delta_swap_out / delta_time;
  if (diskstats_success) {
    metrics_lib_->SendToUMA(kReadSectorsHistogramName,
                            read_sectors_per_second,
                            1,
                            kSectorsIOMax,
                            kSectorsBuckets);
    metrics_lib_->SendToUMA(kWriteSectorsHistogramName,
                            write_sectors_per_second,
                            1,
                            kSectorsIOMax,
                            kSectorsBuckets);
  }
  if (vmstats_success) {
    metrics_lib_->SendToUMA(kPageFaultsHistogramName,
                            page_faults_per_second,
                            1,
                            kPageFaultsMax,
                            kPageFaultsBuckets);
    metrics_lib_->SendToUMA(kSwapInHistogramName,
                            swap_in_per_second,
                            1,
                            kPageFaultsMax,
                            kPageFaultsBuckets);
    metrics_lib_->SendToUMA(kSwapOutHistogramName,
                            swap_out_per_second,
                            1,
                            kPageFaultsMax,
                            kPageFaultsBuckets);
  }
}
