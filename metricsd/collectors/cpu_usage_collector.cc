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

#include "collectors/cpu_usage_collector.h"

#include <base/bind.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/message_loop/message_loop.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/sys_info.h>

#include "metrics/metrics_library.h"

namespace {

const char kCpuUsagePercent[] = "Platform.CpuUsage.Percent";
const char kMetricsProcStatFileName[] = "/proc/stat";
const int kMetricsProcStatFirstLineItemsCount = 11;

// Collect every minute.
const int kCollectionIntervalSecs = 60;

}  // namespace

using base::TimeDelta;

CpuUsageCollector::CpuUsageCollector(MetricsLibraryInterface* metrics_library) {
  CHECK(metrics_library);
  metrics_lib_ = metrics_library;
  collect_interval_ = TimeDelta::FromSeconds(kCollectionIntervalSecs);
}

void CpuUsageCollector::Init() {
  num_cpu_ = base::SysInfo::NumberOfProcessors();

  // Get ticks per second (HZ) on this system.
  // Sysconf cannot fail, so no sanity checks are needed.
  ticks_per_second_ = sysconf(_SC_CLK_TCK);
  CHECK_GT(ticks_per_second_, uint64_t(0))
      << "Number of ticks per seconds should be positive.";

  latest_cpu_use_ = GetCumulativeCpuUse();
}

void CpuUsageCollector::CollectCallback() {
  Collect();
  Schedule();
}

void CpuUsageCollector::Schedule() {
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&CpuUsageCollector::CollectCallback, base::Unretained(this)),
      collect_interval_);
}

void CpuUsageCollector::Collect() {
  TimeDelta cpu_use = GetCumulativeCpuUse();
  TimeDelta diff_per_cpu = (cpu_use - latest_cpu_use_) / num_cpu_;
  latest_cpu_use_ = cpu_use;

  // Report the cpu usage as a percentage of the total cpu usage possible.
  int percent_use = diff_per_cpu.InMilliseconds() * 100 /
      (kCollectionIntervalSecs * 1000);

  metrics_lib_->SendEnumToUMA(kCpuUsagePercent, percent_use, 101);
}

TimeDelta CpuUsageCollector::GetCumulativeCpuUse() {
  base::FilePath proc_stat_path(kMetricsProcStatFileName);
  std::string proc_stat_string;
  if (!base::ReadFileToString(proc_stat_path, &proc_stat_string)) {
    LOG(WARNING) << "cannot open " << kMetricsProcStatFileName;
    return TimeDelta();
  }

  uint64_t user_ticks, user_nice_ticks, system_ticks;
  if (!ParseProcStat(proc_stat_string, &user_ticks, &user_nice_ticks,
                     &system_ticks)) {
    return TimeDelta();
  }

  uint64_t total = user_ticks + user_nice_ticks + system_ticks;
  return TimeDelta::FromMicroseconds(
      total * 1000 * 1000 / ticks_per_second_);
}

bool CpuUsageCollector::ParseProcStat(const std::string& stat_content,
                                      uint64_t *user_ticks,
                                      uint64_t *user_nice_ticks,
                                      uint64_t *system_ticks) {
  std::vector<std::string> proc_stat_lines = base::SplitString(
      stat_content, "\n", base::TRIM_WHITESPACE, base::SPLIT_WANT_ALL);
  if (proc_stat_lines.empty()) {
    LOG(WARNING) << "No lines found in " << kMetricsProcStatFileName;
    return false;
  }
  std::vector<std::string> proc_stat_totals =
      base::SplitString(proc_stat_lines[0], base::kWhitespaceASCII,
                        base::KEEP_WHITESPACE, base::SPLIT_WANT_NONEMPTY);

  if (proc_stat_totals.size() != kMetricsProcStatFirstLineItemsCount ||
      proc_stat_totals[0] != "cpu" ||
      !base::StringToUint64(proc_stat_totals[1], user_ticks) ||
      !base::StringToUint64(proc_stat_totals[2], user_nice_ticks) ||
      !base::StringToUint64(proc_stat_totals[3], system_ticks)) {
    LOG(WARNING) << "cannot parse first line: " << proc_stat_lines[0];
    return false;
  }
  return true;
}
