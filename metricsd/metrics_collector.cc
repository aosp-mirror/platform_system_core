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

#include "metrics_collector.h"

#include <sysexits.h>
#include <time.h>

#include <memory>

#include <base/bind.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/hash.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <brillo/binder_watcher.h>
#include <brillo/osrelease_reader.h>

#include "constants.h"
#include "metrics_collector_service_impl.h"

using base::FilePath;
using base::StringPrintf;
using base::Time;
using base::TimeDelta;
using base::TimeTicks;
using chromeos_metrics::PersistentInteger;
using std::map;
using std::string;
using std::vector;

namespace {

const int kSecondsPerMinute = 60;
const int kMinutesPerHour = 60;
const int kHoursPerDay = 24;
const int kMinutesPerDay = kHoursPerDay * kMinutesPerHour;
const int kSecondsPerDay = kSecondsPerMinute * kMinutesPerDay;
const int kDaysPerWeek = 7;
const int kSecondsPerWeek = kSecondsPerDay * kDaysPerWeek;

// Interval between calls to UpdateStats().
const uint32_t kUpdateStatsIntervalMs = 300000;

const char kKernelCrashDetectedFile[] =
    "/data/misc/crash_reporter/run/kernel-crash-detected";
const char kUncleanShutdownDetectedFile[] =
    "/var/run/unclean-shutdown-detected";

const int kMetricMeminfoInterval = 30;    // seconds

const char kMeminfoFileName[] = "/proc/meminfo";
const char kVmStatFileName[] = "/proc/vmstat";

const char kWeaveComponent[] = "metrics";
const char kWeaveTrait[] = "_metrics";

}  // namespace

// Zram sysfs entries.

const char MetricsCollector::kComprDataSizeName[] = "compr_data_size";
const char MetricsCollector::kOrigDataSizeName[] = "orig_data_size";
const char MetricsCollector::kZeroPagesName[] = "zero_pages";

// Memory use stats collection intervals.  We collect some memory use interval
// at these intervals after boot, and we stop collecting after the last one,
// with the assumption that in most cases the memory use won't change much
// after that.
static const int kMemuseIntervals[] = {
  1 * kSecondsPerMinute,    // 1 minute mark
  4 * kSecondsPerMinute,    // 5 minute mark
  25 * kSecondsPerMinute,   // 0.5 hour mark
  120 * kSecondsPerMinute,  // 2.5 hour mark
  600 * kSecondsPerMinute,  // 12.5 hour mark
};

MetricsCollector::MetricsCollector()
    : memuse_final_time_(0),
      memuse_interval_index_(0) {}

MetricsCollector::~MetricsCollector() {
}

// static
double MetricsCollector::GetActiveTime() {
  struct timespec ts;
  int r = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (r < 0) {
    PLOG(WARNING) << "clock_gettime(CLOCK_MONOTONIC) failed";
    return 0;
  } else {
    return ts.tv_sec + static_cast<double>(ts.tv_nsec) / (1000 * 1000 * 1000);
  }
}

int MetricsCollector::Run() {
  if (CheckSystemCrash(kKernelCrashDetectedFile)) {
    ProcessKernelCrash();
  }

  if (CheckSystemCrash(kUncleanShutdownDetectedFile)) {
    ProcessUncleanShutdown();
  }

  // On OS version change, clear version stats (which are reported daily).
  int32_t version = GetOsVersionHash();
  if (version_cycle_->Get() != version) {
    version_cycle_->Set(version);
    kernel_crashes_version_count_->Set(0);
    version_cumulative_active_use_->Set(0);
    version_cumulative_cpu_use_->Set(0);
  }

  // Start metricscollectorservice
  android::sp<BnMetricsCollectorServiceImpl> metrics_collector_service =
      new BnMetricsCollectorServiceImpl(this);
  android::status_t status = android::defaultServiceManager()->addService(
      metrics_collector_service->getInterfaceDescriptor(),
      metrics_collector_service);
  CHECK(status == android::OK)
      << "failed to register service metricscollectorservice";

  // Watch Binder events in the main loop
  brillo::BinderWatcher binder_watcher;
  CHECK(binder_watcher.Init()) << "Binder FD watcher init failed";
  return brillo::Daemon::Run();
}

uint32_t MetricsCollector::GetOsVersionHash() {
  brillo::OsReleaseReader reader;
  reader.Load();
  string version;
  if (!reader.GetString(metrics::kProductVersion, &version)) {
    LOG(ERROR) << "failed to read the product version.";
    version = metrics::kDefaultVersion;
  }

  uint32_t version_hash = base::Hash(version);
  if (testing_) {
    version_hash = 42;  // return any plausible value for the hash
  }
  return version_hash;
}

void MetricsCollector::Init(bool testing, MetricsLibraryInterface* metrics_lib,
                            const string& diskstats_path,
                            const base::FilePath& private_metrics_directory,
                            const base::FilePath& shared_metrics_directory) {
  CHECK(metrics_lib);
  testing_ = testing;
  shared_metrics_directory_ = shared_metrics_directory;
  metrics_lib_ = metrics_lib;

  daily_active_use_.reset(new PersistentInteger("Platform.UseTime.PerDay",
                                                private_metrics_directory));
  version_cumulative_active_use_.reset(new PersistentInteger(
      "Platform.CumulativeUseTime", private_metrics_directory));
  version_cumulative_cpu_use_.reset(new PersistentInteger(
      "Platform.CumulativeCpuTime", private_metrics_directory));

  kernel_crash_interval_.reset(new PersistentInteger(
      "Platform.KernelCrashInterval", private_metrics_directory));
  unclean_shutdown_interval_.reset(new PersistentInteger(
      "Platform.UncleanShutdownInterval", private_metrics_directory));
  user_crash_interval_.reset(new PersistentInteger("Platform.UserCrashInterval",
                                                   private_metrics_directory));

  any_crashes_daily_count_.reset(new PersistentInteger(
      "Platform.AnyCrashes.PerDay", private_metrics_directory));
  any_crashes_weekly_count_.reset(new PersistentInteger(
      "Platform.AnyCrashes.PerWeek", private_metrics_directory));
  user_crashes_daily_count_.reset(new PersistentInteger(
      "Platform.UserCrashes.PerDay", private_metrics_directory));
  user_crashes_weekly_count_.reset(new PersistentInteger(
      "Platform.UserCrashes.PerWeek", private_metrics_directory));
  kernel_crashes_daily_count_.reset(new PersistentInteger(
      "Platform.KernelCrashes.PerDay", private_metrics_directory));
  kernel_crashes_weekly_count_.reset(new PersistentInteger(
      "Platform.KernelCrashes.PerWeek", private_metrics_directory));
  kernel_crashes_version_count_.reset(new PersistentInteger(
      "Platform.KernelCrashesSinceUpdate", private_metrics_directory));
  unclean_shutdowns_daily_count_.reset(new PersistentInteger(
      "Platform.UncleanShutdown.PerDay", private_metrics_directory));
  unclean_shutdowns_weekly_count_.reset(new PersistentInteger(
      "Platform.UncleanShutdowns.PerWeek", private_metrics_directory));

  daily_cycle_.reset(
      new PersistentInteger("daily.cycle", private_metrics_directory));
  weekly_cycle_.reset(
      new PersistentInteger("weekly.cycle", private_metrics_directory));
  version_cycle_.reset(
      new PersistentInteger("version.cycle", private_metrics_directory));

  disk_usage_collector_.reset(new DiskUsageCollector(metrics_lib_));
  averaged_stats_collector_.reset(
      new AveragedStatisticsCollector(metrics_lib_, diskstats_path,
                                      kVmStatFileName));
  cpu_usage_collector_.reset(new CpuUsageCollector(metrics_lib_));
}

int MetricsCollector::OnInit() {
  int return_code = brillo::Daemon::OnInit();
  if (return_code != EX_OK)
    return return_code;

  StatsReporterInit();

  // Start collecting meminfo stats.
  ScheduleMeminfoCallback(kMetricMeminfoInterval);
  memuse_final_time_ = GetActiveTime() + kMemuseIntervals[0];
  ScheduleMemuseCallback(kMemuseIntervals[0]);

  if (testing_)
    return EX_OK;

  weave_service_subscription_ = weaved::Service::Connect(
      brillo::MessageLoop::current(),
      base::Bind(&MetricsCollector::OnWeaveServiceConnected,
                 weak_ptr_factory_.GetWeakPtr()));

  latest_cpu_use_microseconds_ = cpu_usage_collector_->GetCumulativeCpuUse();
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsCollector::HandleUpdateStatsTimeout,
                 weak_ptr_factory_.GetWeakPtr()),
      base::TimeDelta::FromMilliseconds(kUpdateStatsIntervalMs));

  return EX_OK;
}

void MetricsCollector::OnWeaveServiceConnected(
    const std::weak_ptr<weaved::Service>& service) {
  service_ = service;
  auto weave_service = service_.lock();
  if (!weave_service)
    return;

  weave_service->AddComponent(kWeaveComponent, {kWeaveTrait}, nullptr);
  weave_service->AddCommandHandler(
      kWeaveComponent, kWeaveTrait, "enableAnalyticsReporting",
      base::Bind(&MetricsCollector::OnEnableMetrics,
                 weak_ptr_factory_.GetWeakPtr()));
  weave_service->AddCommandHandler(
      kWeaveComponent, kWeaveTrait, "disableAnalyticsReporting",
      base::Bind(&MetricsCollector::OnDisableMetrics,
                 weak_ptr_factory_.GetWeakPtr()));

  UpdateWeaveState();
}

void MetricsCollector::OnEnableMetrics(
    std::unique_ptr<weaved::Command> command) {
  if (base::WriteFile(
          shared_metrics_directory_.Append(metrics::kConsentFileName), "", 0) !=
      0) {
    PLOG(ERROR) << "Could not create the consent file.";
    command->Abort("metrics_error", "Could not create the consent file",
                   nullptr);
    return;
  }

  UpdateWeaveState();
  command->Complete({}, nullptr);
}

void MetricsCollector::OnDisableMetrics(
    std::unique_ptr<weaved::Command> command) {
  if (!base::DeleteFile(
          shared_metrics_directory_.Append(metrics::kConsentFileName), false)) {
    PLOG(ERROR) << "Could not delete the consent file.";
    command->Abort("metrics_error", "Could not delete the consent file",
                   nullptr);
    return;
  }

  UpdateWeaveState();
  command->Complete({}, nullptr);
}

void MetricsCollector::UpdateWeaveState() {
  auto weave_service = service_.lock();
  if (!weave_service)
    return;

  std::string enabled =
      metrics_lib_->AreMetricsEnabled() ? "enabled" : "disabled";

  if (!weave_service->SetStateProperty(kWeaveComponent, kWeaveTrait,
                                       "analyticsReportingState",
                                       *brillo::ToValue(enabled),
                                       nullptr)) {
    LOG(ERROR) << "failed to update weave's state";
  }
}

void MetricsCollector::ProcessUserCrash() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendAndResetCrashIntervalSample(user_crash_interval_);

  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
  user_crashes_daily_count_->Add(1);
  user_crashes_weekly_count_->Add(1);
}

void MetricsCollector::ProcessKernelCrash() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendAndResetCrashIntervalSample(kernel_crash_interval_);

  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
  kernel_crashes_daily_count_->Add(1);
  kernel_crashes_weekly_count_->Add(1);

  kernel_crashes_version_count_->Add(1);
}

void MetricsCollector::ProcessUncleanShutdown() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendAndResetCrashIntervalSample(unclean_shutdown_interval_);

  unclean_shutdowns_daily_count_->Add(1);
  unclean_shutdowns_weekly_count_->Add(1);
  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
}

bool MetricsCollector::CheckSystemCrash(const string& crash_file) {
  FilePath crash_detected(crash_file);
  if (!base::PathExists(crash_detected))
    return false;

  // Deletes the crash-detected file so that the daemon doesn't report
  // another kernel crash in case it's restarted.
  base::DeleteFile(crash_detected, false);  // not recursive
  return true;
}

void MetricsCollector::StatsReporterInit() {
  disk_usage_collector_->Schedule();

  cpu_usage_collector_->Init();
  cpu_usage_collector_->Schedule();

  // Don't start a collection cycle during the first run to avoid delaying the
  // boot.
  averaged_stats_collector_->ScheduleWait();
}

void MetricsCollector::ScheduleMeminfoCallback(int wait) {
  if (testing_) {
    return;
  }
  base::TimeDelta waitDelta = base::TimeDelta::FromSeconds(wait);
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsCollector::MeminfoCallback,
                 weak_ptr_factory_.GetWeakPtr(), waitDelta),
      waitDelta);
}

void MetricsCollector::MeminfoCallback(base::TimeDelta wait) {
  string meminfo_raw;
  const FilePath meminfo_path(kMeminfoFileName);
  if (!base::ReadFileToString(meminfo_path, &meminfo_raw)) {
    LOG(WARNING) << "cannot read " << meminfo_path.value().c_str();
    return;
  }
  // Make both calls even if the first one fails.
  if (ProcessMeminfo(meminfo_raw)) {
    base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
        base::Bind(&MetricsCollector::MeminfoCallback,
                   weak_ptr_factory_.GetWeakPtr(), wait),
        wait);
  }
}

// static
bool MetricsCollector::ReadFileToUint64(const base::FilePath& path,
                                         uint64_t* value) {
  std::string content;
  if (!base::ReadFileToString(path, &content)) {
    PLOG(WARNING) << "cannot read " << path.MaybeAsASCII();
    return false;
  }
  // Remove final newline.
  base::TrimWhitespaceASCII(content, base::TRIM_TRAILING, &content);
  if (!base::StringToUint64(content, value)) {
    LOG(WARNING) << "invalid integer: " << content;
    return false;
  }
  return true;
}

bool MetricsCollector::ReportZram(const base::FilePath& zram_dir) {
  // Data sizes are in bytes.  |zero_pages| is in number of pages.
  uint64_t compr_data_size, orig_data_size, zero_pages;
  const size_t page_size = 4096;

  if (!ReadFileToUint64(zram_dir.Append(kComprDataSizeName),
                        &compr_data_size) ||
      !ReadFileToUint64(zram_dir.Append(kOrigDataSizeName), &orig_data_size) ||
      !ReadFileToUint64(zram_dir.Append(kZeroPagesName), &zero_pages)) {
    return false;
  }

  // |orig_data_size| does not include zero-filled pages.
  orig_data_size += zero_pages * page_size;

  const int compr_data_size_mb = compr_data_size >> 20;
  const int savings_mb = (orig_data_size - compr_data_size) >> 20;
  const int zero_ratio_percent = zero_pages * page_size * 100 / orig_data_size;

  // Report compressed size in megabytes.  100 MB or less has little impact.
  SendSample("Platform.ZramCompressedSize", compr_data_size_mb, 100, 4000, 50);
  SendSample("Platform.ZramSavings", savings_mb, 100, 4000, 50);
  // The compression ratio is multiplied by 100 for better resolution.  The
  // ratios of interest are between 1 and 6 (100% and 600% as reported).  We
  // don't want samples when very little memory is being compressed.
  if (compr_data_size_mb >= 1) {
    SendSample("Platform.ZramCompressionRatioPercent",
               orig_data_size * 100 / compr_data_size, 100, 600, 50);
  }
  // The values of interest for zero_pages are between 1MB and 1GB.  The units
  // are number of pages.
  SendSample("Platform.ZramZeroPages", zero_pages, 256, 256 * 1024, 50);
  SendSample("Platform.ZramZeroRatioPercent", zero_ratio_percent, 1, 50, 50);

  return true;
}

bool MetricsCollector::ProcessMeminfo(const string& meminfo_raw) {
  static const MeminfoRecord fields_array[] = {
    { "MemTotal", "MemTotal" },  // SPECIAL CASE: total system memory
    { "MemFree", "MemFree" },
    { "Buffers", "Buffers" },
    { "Cached", "Cached" },
    // { "SwapCached", "SwapCached" },
    { "Active", "Active" },
    { "Inactive", "Inactive" },
    { "ActiveAnon", "Active(anon)" },
    { "InactiveAnon", "Inactive(anon)" },
    { "ActiveFile" , "Active(file)" },
    { "InactiveFile", "Inactive(file)" },
    { "Unevictable", "Unevictable", kMeminfoOp_HistLog },
    // { "Mlocked", "Mlocked" },
    { "SwapTotal", "SwapTotal", kMeminfoOp_SwapTotal },
    { "SwapFree", "SwapFree", kMeminfoOp_SwapFree },
    // { "Dirty", "Dirty" },
    // { "Writeback", "Writeback" },
    { "AnonPages", "AnonPages" },
    { "Mapped", "Mapped" },
    { "Shmem", "Shmem", kMeminfoOp_HistLog },
    { "Slab", "Slab", kMeminfoOp_HistLog },
    // { "SReclaimable", "SReclaimable" },
    // { "SUnreclaim", "SUnreclaim" },
  };
  vector<MeminfoRecord> fields(fields_array,
                               fields_array + arraysize(fields_array));
  if (!FillMeminfo(meminfo_raw, &fields)) {
    return false;
  }
  int total_memory = fields[0].value;
  if (total_memory == 0) {
    // this "cannot happen"
    LOG(WARNING) << "borked meminfo parser";
    return false;
  }
  int swap_total = 0;
  int swap_free = 0;
  // Send all fields retrieved, except total memory.
  for (unsigned int i = 1; i < fields.size(); i++) {
    string metrics_name = base::StringPrintf("Platform.Meminfo%s",
                                             fields[i].name);
    int percent;
    switch (fields[i].op) {
      case kMeminfoOp_HistPercent:
        // report value as percent of total memory
        percent = fields[i].value * 100 / total_memory;
        SendLinearSample(metrics_name, percent, 100, 101);
        break;
      case kMeminfoOp_HistLog:
        // report value in kbytes, log scale, 4Gb max
        SendSample(metrics_name, fields[i].value, 1, 4 * 1000 * 1000, 100);
        break;
      case kMeminfoOp_SwapTotal:
        swap_total = fields[i].value;
      case kMeminfoOp_SwapFree:
        swap_free = fields[i].value;
        break;
    }
  }
  if (swap_total > 0) {
    int swap_used = swap_total - swap_free;
    int swap_used_percent = swap_used * 100 / swap_total;
    SendSample("Platform.MeminfoSwapUsed", swap_used, 1, 8 * 1000 * 1000, 100);
    SendLinearSample("Platform.MeminfoSwapUsed.Percent", swap_used_percent,
                     100, 101);
  }
  return true;
}

bool MetricsCollector::FillMeminfo(const string& meminfo_raw,
                                    vector<MeminfoRecord>* fields) {
  vector<std::string> lines =
      base::SplitString(meminfo_raw, "\n", base::KEEP_WHITESPACE,
                        base::SPLIT_WANT_NONEMPTY);

  // Scan meminfo output and collect field values.  Each field name has to
  // match a meminfo entry (case insensitive) after removing non-alpha
  // characters from the entry.
  size_t ifield = 0;
  for (size_t iline = 0;
       iline < lines.size() && ifield < fields->size();
       iline++) {
    vector<string> tokens =
        base::SplitString(lines[iline], ": ", base::KEEP_WHITESPACE,
                          base::SPLIT_WANT_NONEMPTY);
    if (strcmp((*fields)[ifield].match, tokens[0].c_str()) == 0) {
      // Name matches. Parse value and save.
      if (!base::StringToInt(tokens[1], &(*fields)[ifield].value)) {
        LOG(WARNING) << "Cound not convert " << tokens[1] << " to int";
        return false;
      }
      ifield++;
    }
  }
  if (ifield < fields->size()) {
    // End of input reached while scanning.
    LOG(WARNING) << "cannot find field " << (*fields)[ifield].match
                 << " and following";
    return false;
  }
  return true;
}

void MetricsCollector::ScheduleMemuseCallback(double interval) {
  if (testing_) {
    return;
  }
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsCollector::MemuseCallback,
                 weak_ptr_factory_.GetWeakPtr()),
      base::TimeDelta::FromSeconds(interval));
}

void MetricsCollector::MemuseCallback() {
  // Since we only care about active time (i.e. uptime minus sleep time) but
  // the callbacks are driven by real time (uptime), we check if we should
  // reschedule this callback due to intervening sleep periods.
  double now = GetActiveTime();
  // Avoid intervals of less than one second.
  double remaining_time = ceil(memuse_final_time_ - now);
  if (remaining_time > 0) {
    ScheduleMemuseCallback(remaining_time);
  } else {
    // Report stats and advance the measurement interval unless there are
    // errors or we've completed the last interval.
    if (MemuseCallbackWork() &&
        memuse_interval_index_ < arraysize(kMemuseIntervals)) {
      double interval = kMemuseIntervals[memuse_interval_index_++];
      memuse_final_time_ = now + interval;
      ScheduleMemuseCallback(interval);
    }
  }
}

bool MetricsCollector::MemuseCallbackWork() {
  string meminfo_raw;
  const FilePath meminfo_path(kMeminfoFileName);
  if (!base::ReadFileToString(meminfo_path, &meminfo_raw)) {
    LOG(WARNING) << "cannot read " << meminfo_path.value().c_str();
    return false;
  }
  return ProcessMemuse(meminfo_raw);
}

bool MetricsCollector::ProcessMemuse(const string& meminfo_raw) {
  static const MeminfoRecord fields_array[] = {
    { "MemTotal", "MemTotal" },  // SPECIAL CASE: total system memory
    { "ActiveAnon", "Active(anon)" },
    { "InactiveAnon", "Inactive(anon)" },
  };
  vector<MeminfoRecord> fields(fields_array,
                               fields_array + arraysize(fields_array));
  if (!FillMeminfo(meminfo_raw, &fields)) {
    return false;
  }
  int total = fields[0].value;
  int active_anon = fields[1].value;
  int inactive_anon = fields[2].value;
  if (total == 0) {
    // this "cannot happen"
    LOG(WARNING) << "borked meminfo parser";
    return false;
  }
  string metrics_name = base::StringPrintf("Platform.MemuseAnon%d",
                                           memuse_interval_index_);
  SendLinearSample(metrics_name, (active_anon + inactive_anon) * 100 / total,
                   100, 101);
  return true;
}

void MetricsCollector::SendSample(const string& name, int sample,
                                   int min, int max, int nbuckets) {
  metrics_lib_->SendToUMA(name, sample, min, max, nbuckets);
}

void MetricsCollector::SendKernelCrashesCumulativeCountStats() {
  // Report the number of crashes for this OS version, but don't clear the
  // counter.  It is cleared elsewhere on version change.
  int64_t crashes_count = kernel_crashes_version_count_->Get();
  SendSample(kernel_crashes_version_count_->Name(),
             crashes_count,
             1,                         // value of first bucket
             500,                       // value of last bucket
             100);                      // number of buckets


  int64_t cpu_use_ms = version_cumulative_cpu_use_->Get();
  SendSample(version_cumulative_cpu_use_->Name(),
             cpu_use_ms / 1000,         // stat is in seconds
             1,                         // device may be used very little...
             8 * 1000 * 1000,           // ... or a lot (a little over 90 days)
             100);

  // On the first run after an autoupdate, cpu_use_ms and active_use_seconds
  // can be zero.  Avoid division by zero.
  if (cpu_use_ms > 0) {
    // Send the crash frequency since update in number of crashes per CPU year.
    SendSample("Logging.KernelCrashesPerCpuYear",
               crashes_count * kSecondsPerDay * 365 * 1000 / cpu_use_ms,
               1,
               1000 * 1000,     // about one crash every 30s of CPU time
               100);
  }

  int64_t active_use_seconds = version_cumulative_active_use_->Get();
  if (active_use_seconds > 0) {
    SendSample(version_cumulative_active_use_->Name(),
               active_use_seconds,
               1,                          // device may be used very little...
               8 * 1000 * 1000,            // ... or a lot (about 90 days)
               100);
    // Same as above, but per year of active time.
    SendSample("Logging.KernelCrashesPerActiveYear",
               crashes_count * kSecondsPerDay * 365 / active_use_seconds,
               1,
               1000 * 1000,     // about one crash every 30s of active time
               100);
  }
}

void MetricsCollector::SendAndResetDailyUseSample(
    const unique_ptr<PersistentInteger>& use) {
  SendSample(use->Name(),
             use->GetAndClear(),
             1,                        // value of first bucket
             kSecondsPerDay,           // value of last bucket
             50);                      // number of buckets
}

void MetricsCollector::SendAndResetCrashIntervalSample(
    const unique_ptr<PersistentInteger>& interval) {
  SendSample(interval->Name(),
             interval->GetAndClear(),
             1,                        // value of first bucket
             4 * kSecondsPerWeek,      // value of last bucket
             50);                      // number of buckets
}

void MetricsCollector::SendAndResetCrashFrequencySample(
    const unique_ptr<PersistentInteger>& frequency) {
  SendSample(frequency->Name(),
             frequency->GetAndClear(),
             1,                        // value of first bucket
             100,                      // value of last bucket
             50);                      // number of buckets
}

void MetricsCollector::SendLinearSample(const string& name, int sample,
                                         int max, int nbuckets) {
  // TODO(semenzato): add a proper linear histogram to the Chrome external
  // metrics API.
  LOG_IF(FATAL, nbuckets != max + 1) << "unsupported histogram scale";
  metrics_lib_->SendEnumToUMA(name, sample, max);
}

void MetricsCollector::UpdateStats(TimeTicks now_ticks,
                                    Time now_wall_time) {
  const int elapsed_seconds = (now_ticks - last_update_stats_time_).InSeconds();
  daily_active_use_->Add(elapsed_seconds);
  version_cumulative_active_use_->Add(elapsed_seconds);
  user_crash_interval_->Add(elapsed_seconds);
  kernel_crash_interval_->Add(elapsed_seconds);
  TimeDelta cpu_use = cpu_usage_collector_->GetCumulativeCpuUse();
  version_cumulative_cpu_use_->Add(
      (cpu_use - latest_cpu_use_microseconds_).InMilliseconds());
  latest_cpu_use_microseconds_ = cpu_use;
  last_update_stats_time_ = now_ticks;

  const TimeDelta since_epoch = now_wall_time - Time::UnixEpoch();
  const int day = since_epoch.InDays();
  const int week = day / 7;

  if (daily_cycle_->Get() != day) {
    daily_cycle_->Set(day);
    SendAndResetDailyUseSample(daily_active_use_);
    SendAndResetCrashFrequencySample(any_crashes_daily_count_);
    SendAndResetCrashFrequencySample(user_crashes_daily_count_);
    SendAndResetCrashFrequencySample(kernel_crashes_daily_count_);
    SendAndResetCrashFrequencySample(unclean_shutdowns_daily_count_);
    SendKernelCrashesCumulativeCountStats();
  }

  if (weekly_cycle_->Get() != week) {
    weekly_cycle_->Set(week);
    SendAndResetCrashFrequencySample(any_crashes_weekly_count_);
    SendAndResetCrashFrequencySample(user_crashes_weekly_count_);
    SendAndResetCrashFrequencySample(kernel_crashes_weekly_count_);
    SendAndResetCrashFrequencySample(unclean_shutdowns_weekly_count_);
  }
}

void MetricsCollector::HandleUpdateStatsTimeout() {
  UpdateStats(TimeTicks::Now(), Time::Now());
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsCollector::HandleUpdateStatsTimeout,
                 weak_ptr_factory_.GetWeakPtr()),
      base::TimeDelta::FromMilliseconds(kUpdateStatsIntervalMs));
}
