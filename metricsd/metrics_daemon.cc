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

#include "metrics_daemon.h"

#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <string.h>
#include <sysexits.h>
#include <time.h>

#include <base/bind.h>
#include <base/files/file_path.h>
#include <base/files/file_util.h>
#include <base/hash.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_split.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <cutils/properties.h>
#include <dbus/dbus.h>
#include <dbus/message.h>

#include "constants.h"
#include "uploader/upload_service.h"

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

const char kCrashReporterInterface[] = "org.chromium.CrashReporter";
const char kCrashReporterUserCrashSignal[] = "UserCrash";
const char kCrashReporterMatchRule[] =
    "type='signal',interface='%s',path='/',member='%s'";

const int kSecondsPerMinute = 60;
const int kMinutesPerHour = 60;
const int kHoursPerDay = 24;
const int kMinutesPerDay = kHoursPerDay * kMinutesPerHour;
const int kSecondsPerDay = kSecondsPerMinute * kMinutesPerDay;
const int kDaysPerWeek = 7;
const int kSecondsPerWeek = kSecondsPerDay * kDaysPerWeek;

// Interval between calls to UpdateStats().
const uint32_t kUpdateStatsIntervalMs = 300000;

const char kKernelCrashDetectedFile[] = "/var/run/kernel-crash-detected";
const char kUncleanShutdownDetectedFile[] =
    "/var/run/unclean-shutdown-detected";

// disk stats metrics

// The {Read,Write}Sectors numbers are in sectors/second.
// A sector is usually 512 bytes.

const char kMetricReadSectorsLongName[] = "Platform.ReadSectorsLong";
const char kMetricWriteSectorsLongName[] = "Platform.WriteSectorsLong";
const char kMetricReadSectorsShortName[] = "Platform.ReadSectorsShort";
const char kMetricWriteSectorsShortName[] = "Platform.WriteSectorsShort";

const int kMetricStatsShortInterval = 1;  // seconds
const int kMetricStatsLongInterval = 30;  // seconds

// Assume a max rate of 250Mb/s for reads (worse for writes) and 512 byte
// sectors.
const int kMetricSectorsIOMax = 500000;  // sectors/second
const int kMetricSectorsBuckets = 50;    // buckets
// Page size is 4k, sector size is 0.5k.  We're not interested in page fault
// rates that the disk cannot sustain.
const int kMetricPageFaultsMax = kMetricSectorsIOMax / 8;
const int kMetricPageFaultsBuckets = 50;

// Major page faults, i.e. the ones that require data to be read from disk.

const char kMetricPageFaultsLongName[] = "Platform.PageFaultsLong";
const char kMetricPageFaultsShortName[] = "Platform.PageFaultsShort";

// Swap in and Swap out

const char kMetricSwapInLongName[] = "Platform.SwapInLong";
const char kMetricSwapInShortName[] = "Platform.SwapInShort";

const char kMetricSwapOutLongName[] = "Platform.SwapOutLong";
const char kMetricSwapOutShortName[] = "Platform.SwapOutShort";

const char kMetricsProcStatFileName[] = "/proc/stat";
const char kVmStatFileName[] = "/proc/vmstat";
const char kMeminfoFileName[] = "/proc/meminfo";
const int kMetricsProcStatFirstLineItemsCount = 11;
const int kDiskMetricsStatItemCount = 11;

// Thermal CPU throttling.

const char kMetricScaledCpuFrequencyName[] =
    "Platform.CpuFrequencyThermalScaling";

}  // namespace

// Zram sysfs entries.

const char MetricsDaemon::kComprDataSizeName[] = "compr_data_size";
const char MetricsDaemon::kOrigDataSizeName[] = "orig_data_size";
const char MetricsDaemon::kZeroPagesName[] = "zero_pages";

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

MetricsDaemon::MetricsDaemon()
    : memuse_final_time_(0),
      memuse_interval_index_(0),
      read_sectors_(0),
      write_sectors_(0),
      vmstats_(),
      stats_state_(kStatsShort),
      stats_initial_time_(0),
      ticks_per_second_(0),
      latest_cpu_use_ticks_(0) {}

MetricsDaemon::~MetricsDaemon() {
}

double MetricsDaemon::GetActiveTime() {
  struct timespec ts;
  int r = clock_gettime(CLOCK_MONOTONIC, &ts);
  if (r < 0) {
    PLOG(WARNING) << "clock_gettime(CLOCK_MONOTONIC) failed";
    return 0;
  } else {
    return ts.tv_sec + static_cast<double>(ts.tv_nsec) / (1000 * 1000 * 1000);
  }
}

int MetricsDaemon::Run() {
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

  return chromeos::DBusDaemon::Run();
}

void MetricsDaemon::RunUploaderTest() {
  upload_service_.reset(new UploadService(
      new SystemProfileCache(true, base::FilePath(config_root_)),
      metrics_lib_,
      server_));
  upload_service_->Init(upload_interval_, metrics_file_);
  upload_service_->UploadEvent();
}

uint32_t MetricsDaemon::GetOsVersionHash() {
  static uint32_t cached_version_hash = 0;
  static bool version_hash_is_cached = false;
  if (version_hash_is_cached)
    return cached_version_hash;
  version_hash_is_cached = true;

  char version[PROPERTY_VALUE_MAX];
  // The version might not be set for development devices. In this case, use the
  // zero version.
  property_get(metrics::kProductVersionProperty, version,
               metrics::kDefaultVersion);

  cached_version_hash = base::Hash(version);
  if (testing_) {
    cached_version_hash = 42;  // return any plausible value for the hash
  }
  return cached_version_hash;
}

void MetricsDaemon::Init(bool testing,
                         bool uploader_active,
                         bool dbus_enabled,
                         MetricsLibraryInterface* metrics_lib,
                         const string& diskstats_path,
                         const string& scaling_max_freq_path,
                         const string& cpuinfo_max_freq_path,
                         const base::TimeDelta& upload_interval,
                         const string& server,
                         const string& metrics_file,
                         const string& config_root) {
  CHECK(metrics_lib);
  testing_ = testing;
  uploader_active_ = uploader_active;
  dbus_enabled_ = dbus_enabled;
  config_root_ = config_root;
  metrics_lib_ = metrics_lib;

  upload_interval_ = upload_interval;
  server_ = server;
  metrics_file_ = metrics_file;

  // Get ticks per second (HZ) on this system.
  // Sysconf cannot fail, so no sanity checks are needed.
  ticks_per_second_ = sysconf(_SC_CLK_TCK);

  daily_active_use_.reset(
      new PersistentInteger("Platform.DailyUseTime"));
  version_cumulative_active_use_.reset(
      new PersistentInteger("Platform.CumulativeDailyUseTime"));
  version_cumulative_cpu_use_.reset(
      new PersistentInteger("Platform.CumulativeCpuTime"));

  kernel_crash_interval_.reset(
      new PersistentInteger("Platform.KernelCrashInterval"));
  unclean_shutdown_interval_.reset(
      new PersistentInteger("Platform.UncleanShutdownInterval"));
  user_crash_interval_.reset(
      new PersistentInteger("Platform.UserCrashInterval"));

  any_crashes_daily_count_.reset(
      new PersistentInteger("Platform.AnyCrashesDaily"));
  any_crashes_weekly_count_.reset(
      new PersistentInteger("Platform.AnyCrashesWeekly"));
  user_crashes_daily_count_.reset(
      new PersistentInteger("Platform.UserCrashesDaily"));
  user_crashes_weekly_count_.reset(
      new PersistentInteger("Platform.UserCrashesWeekly"));
  kernel_crashes_daily_count_.reset(
      new PersistentInteger("Platform.KernelCrashesDaily"));
  kernel_crashes_weekly_count_.reset(
      new PersistentInteger("Platform.KernelCrashesWeekly"));
  kernel_crashes_version_count_.reset(
      new PersistentInteger("Platform.KernelCrashesSinceUpdate"));
  unclean_shutdowns_daily_count_.reset(
      new PersistentInteger("Platform.UncleanShutdownsDaily"));
  unclean_shutdowns_weekly_count_.reset(
      new PersistentInteger("Platform.UncleanShutdownsWeekly"));

  daily_cycle_.reset(new PersistentInteger("daily.cycle"));
  weekly_cycle_.reset(new PersistentInteger("weekly.cycle"));
  version_cycle_.reset(new PersistentInteger("version.cycle"));

  diskstats_path_ = diskstats_path;
  scaling_max_freq_path_ = scaling_max_freq_path;
  cpuinfo_max_freq_path_ = cpuinfo_max_freq_path;

  // If testing, initialize Stats Reporter without connecting DBus
  if (testing_)
    StatsReporterInit();
}

int MetricsDaemon::OnInit() {
  int return_code = dbus_enabled_ ? chromeos::DBusDaemon::OnInit() :
      chromeos::Daemon::OnInit();
  if (return_code != EX_OK)
    return return_code;

  StatsReporterInit();

  // Start collecting meminfo stats.
  ScheduleMeminfoCallback(kMetricMeminfoInterval);
  memuse_final_time_ = GetActiveTime() + kMemuseIntervals[0];
  ScheduleMemuseCallback(kMemuseIntervals[0]);

  if (testing_)
    return EX_OK;

  if (dbus_enabled_) {
    bus_->AssertOnDBusThread();
    CHECK(bus_->SetUpAsyncOperations());

    if (bus_->is_connected()) {
      const std::string match_rule =
          base::StringPrintf(kCrashReporterMatchRule,
                             kCrashReporterInterface,
                             kCrashReporterUserCrashSignal);

      bus_->AddFilterFunction(&MetricsDaemon::MessageFilter, this);

      DBusError error;
      dbus_error_init(&error);
      bus_->AddMatch(match_rule, &error);

      if (dbus_error_is_set(&error)) {
        LOG(ERROR) << "Failed to add match rule \"" << match_rule << "\". Got "
            << error.name << ": " << error.message;
        return EX_SOFTWARE;
      }
    } else {
      LOG(ERROR) << "DBus isn't connected.";
      return EX_UNAVAILABLE;
    }
  }

  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsDaemon::HandleUpdateStatsTimeout,
                 base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(kUpdateStatsIntervalMs));

  if (uploader_active_) {
    upload_service_.reset(
        new UploadService(new SystemProfileCache(), metrics_lib_, server_));
    upload_service_->Init(upload_interval_, metrics_file_);
  }

  return EX_OK;
}

void MetricsDaemon::OnShutdown(int* return_code) {
  if (!testing_ && dbus_enabled_ && bus_->is_connected()) {
    const std::string match_rule =
        base::StringPrintf(kCrashReporterMatchRule,
                           kCrashReporterInterface,
                           kCrashReporterUserCrashSignal);

    bus_->RemoveFilterFunction(&MetricsDaemon::MessageFilter, this);

    DBusError error;
    dbus_error_init(&error);
    bus_->RemoveMatch(match_rule, &error);

    if (dbus_error_is_set(&error)) {
      LOG(ERROR) << "Failed to remove match rule \"" << match_rule << "\". Got "
          << error.name << ": " << error.message;
    }
  }
  chromeos::DBusDaemon::OnShutdown(return_code);
}

// static
DBusHandlerResult MetricsDaemon::MessageFilter(DBusConnection* connection,
                                               DBusMessage* message,
                                               void* user_data) {
  int message_type = dbus_message_get_type(message);
  if (message_type != DBUS_MESSAGE_TYPE_SIGNAL) {
    DLOG(WARNING) << "unexpected message type " << message_type;
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  // Signal messages always have interfaces.
  const std::string interface(dbus_message_get_interface(message));
  const std::string member(dbus_message_get_member(message));
  DLOG(INFO) << "Got " << interface << "." << member << " D-Bus signal";

  MetricsDaemon* daemon = static_cast<MetricsDaemon*>(user_data);

  DBusMessageIter iter;
  dbus_message_iter_init(message, &iter);
  if (interface == kCrashReporterInterface) {
    CHECK_EQ(member, kCrashReporterUserCrashSignal);
    daemon->ProcessUserCrash();
  } else {
    // Ignore messages from the bus itself.
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
  }

  return DBUS_HANDLER_RESULT_HANDLED;
}

// One might argue that parts of this should go into
// chromium/src/base/sys_info_chromeos.c instead, but put it here for now.

TimeDelta MetricsDaemon::GetIncrementalCpuUse() {
  FilePath proc_stat_path = FilePath(kMetricsProcStatFileName);
  std::string proc_stat_string;
  if (!base::ReadFileToString(proc_stat_path, &proc_stat_string)) {
    LOG(WARNING) << "cannot open " << kMetricsProcStatFileName;
    return TimeDelta();
  }

  std::vector<std::string> proc_stat_lines;
  base::SplitString(proc_stat_string, '\n', &proc_stat_lines);
  if (proc_stat_lines.empty()) {
    LOG(WARNING) << "cannot parse " << kMetricsProcStatFileName
                 << ": " << proc_stat_string;
    return TimeDelta();
  }
  std::vector<std::string> proc_stat_totals;
  base::SplitStringAlongWhitespace(proc_stat_lines[0], &proc_stat_totals);

  uint64_t user_ticks, user_nice_ticks, system_ticks;
  if (proc_stat_totals.size() != kMetricsProcStatFirstLineItemsCount ||
      proc_stat_totals[0] != "cpu" ||
      !base::StringToUint64(proc_stat_totals[1], &user_ticks) ||
      !base::StringToUint64(proc_stat_totals[2], &user_nice_ticks) ||
      !base::StringToUint64(proc_stat_totals[3], &system_ticks)) {
    LOG(WARNING) << "cannot parse first line: " << proc_stat_lines[0];
    return TimeDelta(base::TimeDelta::FromSeconds(0));
  }

  uint64_t total_cpu_use_ticks = user_ticks + user_nice_ticks + system_ticks;

  // Sanity check.
  if (total_cpu_use_ticks < latest_cpu_use_ticks_) {
    LOG(WARNING) << "CPU time decreasing from " << latest_cpu_use_ticks_
                 << " to " << total_cpu_use_ticks;
    return TimeDelta();
  }

  uint64_t diff = total_cpu_use_ticks - latest_cpu_use_ticks_;
  latest_cpu_use_ticks_ = total_cpu_use_ticks;
  // Use microseconds to avoid significant truncations.
  return base::TimeDelta::FromMicroseconds(
      diff * 1000 * 1000 / ticks_per_second_);
}

void MetricsDaemon::ProcessUserCrash() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendCrashIntervalSample(user_crash_interval_);

  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
  user_crashes_daily_count_->Add(1);
  user_crashes_weekly_count_->Add(1);
}

void MetricsDaemon::ProcessKernelCrash() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendCrashIntervalSample(kernel_crash_interval_);

  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
  kernel_crashes_daily_count_->Add(1);
  kernel_crashes_weekly_count_->Add(1);

  kernel_crashes_version_count_->Add(1);
}

void MetricsDaemon::ProcessUncleanShutdown() {
  // Counts the active time up to now.
  UpdateStats(TimeTicks::Now(), Time::Now());

  // Reports the active use time since the last crash and resets it.
  SendCrashIntervalSample(unclean_shutdown_interval_);

  unclean_shutdowns_daily_count_->Add(1);
  unclean_shutdowns_weekly_count_->Add(1);
  any_crashes_daily_count_->Add(1);
  any_crashes_weekly_count_->Add(1);
}

bool MetricsDaemon::CheckSystemCrash(const string& crash_file) {
  FilePath crash_detected(crash_file);
  if (!base::PathExists(crash_detected))
    return false;

  // Deletes the crash-detected file so that the daemon doesn't report
  // another kernel crash in case it's restarted.
  base::DeleteFile(crash_detected, false);  // not recursive
  return true;
}

void MetricsDaemon::StatsReporterInit() {
  DiskStatsReadStats(&read_sectors_, &write_sectors_);
  VmStatsReadStats(&vmstats_);
  // The first time around just run the long stat, so we don't delay boot.
  stats_state_ = kStatsLong;
  stats_initial_time_ = GetActiveTime();
  if (stats_initial_time_ < 0) {
    LOG(WARNING) << "not collecting disk stats";
  } else {
    ScheduleStatsCallback(kMetricStatsLongInterval);
  }
}

void MetricsDaemon::ScheduleStatsCallback(int wait) {
  if (testing_) {
    return;
  }
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsDaemon::StatsCallback, base::Unretained(this)),
      base::TimeDelta::FromSeconds(wait));
}

bool MetricsDaemon::DiskStatsReadStats(uint64_t* read_sectors,
                                       uint64_t* write_sectors) {
  CHECK(read_sectors);
  CHECK(write_sectors);
  std::string line;
  if (diskstats_path_.empty()) {
    return false;
  }

  if (!base::ReadFileToString(base::FilePath(diskstats_path_), &line)) {
    PLOG(WARNING) << "Could not read disk stats from " << diskstats_path_;
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

bool MetricsDaemon::VmStatsParseStats(const char* stats,
                                      struct VmstatRecord* record) {
  CHECK(stats);
  CHECK(record);
  base::StringPairs pairs;
  base::SplitStringIntoKeyValuePairs(stats, ' ', '\n', &pairs);

  for (base::StringPairs::iterator it = pairs.begin(); it != pairs.end(); ++it) {
    if (it->first == "pgmajfault" &&
        !base::StringToUint64(it->second, &record->page_faults_)) {
      return false;
    }
    if (it->first == "pswpin" &&
        !base::StringToUint64(it->second, &record->swap_in_)) {
      return false;
    }
    if (it->first == "pswpout" &&
        !base::StringToUint64(it->second, &record->swap_out_)) {
      return false;
    }
  }
  return true;
}

bool MetricsDaemon::VmStatsReadStats(struct VmstatRecord* stats) {
  CHECK(stats);
  string value_string;
  if (!base::ReadFileToString(base::FilePath(kVmStatFileName), &value_string)) {
    LOG(WARNING) << "cannot read " << kVmStatFileName;
    return false;
  }
  return VmStatsParseStats(value_string.c_str(), stats);
}

bool MetricsDaemon::ReadFreqToInt(const string& sysfs_file_name, int* value) {
  const FilePath sysfs_path(sysfs_file_name);
  string value_string;
  if (!base::ReadFileToString(sysfs_path, &value_string)) {
    LOG(WARNING) << "cannot read " << sysfs_path.value().c_str();
    return false;
  }
  if (!base::RemoveChars(value_string, "\n", &value_string)) {
    LOG(WARNING) << "no newline in " << value_string;
    // Continue even though the lack of newline is suspicious.
  }
  if (!base::StringToInt(value_string, value)) {
    LOG(WARNING) << "cannot convert " << value_string << " to int";
    return false;
  }
  return true;
}

void MetricsDaemon::SendCpuThrottleMetrics() {
  // |max_freq| is 0 only the first time through.
  static int max_freq = 0;
  if (max_freq == -1)
    // Give up, as sysfs did not report max_freq correctly.
    return;
  if (max_freq == 0 || testing_) {
    // One-time initialization of max_freq.  (Every time when testing.)
    if (!ReadFreqToInt(cpuinfo_max_freq_path_, &max_freq)) {
      max_freq = -1;
      return;
    }
    if (max_freq == 0) {
      LOG(WARNING) << "sysfs reports 0 max CPU frequency\n";
      max_freq = -1;
      return;
    }
    if (max_freq % 10000 == 1000) {
      // Special case: system has turbo mode, and max non-turbo frequency is
      // max_freq - 1000.  This relies on "normal" (non-turbo) frequencies
      // being multiples of (at least) 10 MHz.  Although there is no guarantee
      // of this, it seems a fairly reasonable assumption.  Otherwise we should
      // read scaling_available_frequencies, sort the frequencies, compare the
      // two highest ones, and check if they differ by 1000 (kHz) (and that's a
      // hack too, no telling when it will change).
      max_freq -= 1000;
    }
  }
  int scaled_freq = 0;
  if (!ReadFreqToInt(scaling_max_freq_path_, &scaled_freq))
    return;
  // Frequencies are in kHz.  If scaled_freq > max_freq, turbo is on, but
  // scaled_freq is not the actual turbo frequency.  We indicate this situation
  // with a 101% value.
  int percent = scaled_freq > max_freq ? 101 : scaled_freq / (max_freq / 100);
  SendLinearSample(kMetricScaledCpuFrequencyName, percent, 101, 102);
}

// Collects disk and vm stats alternating over a short and a long interval.

void MetricsDaemon::StatsCallback() {
  uint64_t read_sectors_now, write_sectors_now;
  struct VmstatRecord vmstats_now;
  double time_now = GetActiveTime();
  double delta_time = time_now - stats_initial_time_;
  if (testing_) {
    // Fake the time when testing.
    delta_time = stats_state_ == kStatsShort ?
        kMetricStatsShortInterval : kMetricStatsLongInterval;
  }
  bool diskstats_success = DiskStatsReadStats(&read_sectors_now,
                                              &write_sectors_now);
  int delta_read = read_sectors_now - read_sectors_;
  int delta_write = write_sectors_now - write_sectors_;
  int read_sectors_per_second = delta_read / delta_time;
  int write_sectors_per_second = delta_write / delta_time;
  bool vmstats_success = VmStatsReadStats(&vmstats_now);
  uint64_t delta_faults = vmstats_now.page_faults_ - vmstats_.page_faults_;
  uint64_t delta_swap_in = vmstats_now.swap_in_ - vmstats_.swap_in_;
  uint64_t delta_swap_out = vmstats_now.swap_out_ - vmstats_.swap_out_;
  uint64_t page_faults_per_second = delta_faults / delta_time;
  uint64_t swap_in_per_second = delta_swap_in / delta_time;
  uint64_t swap_out_per_second = delta_swap_out / delta_time;

  switch (stats_state_) {
    case kStatsShort:
      if (diskstats_success) {
        SendSample(kMetricReadSectorsShortName,
                   read_sectors_per_second,
                   1,
                   kMetricSectorsIOMax,
                   kMetricSectorsBuckets);
        SendSample(kMetricWriteSectorsShortName,
                   write_sectors_per_second,
                   1,
                   kMetricSectorsIOMax,
                   kMetricSectorsBuckets);
      }
      if (vmstats_success) {
        SendSample(kMetricPageFaultsShortName,
                   page_faults_per_second,
                   1,
                   kMetricPageFaultsMax,
                   kMetricPageFaultsBuckets);
        SendSample(kMetricSwapInShortName,
                   swap_in_per_second,
                   1,
                   kMetricPageFaultsMax,
                   kMetricPageFaultsBuckets);
        SendSample(kMetricSwapOutShortName,
                   swap_out_per_second,
                   1,
                   kMetricPageFaultsMax,
                   kMetricPageFaultsBuckets);
      }
      // Schedule long callback.
      stats_state_ = kStatsLong;
      ScheduleStatsCallback(kMetricStatsLongInterval -
                            kMetricStatsShortInterval);
      break;
    case kStatsLong:
      if (diskstats_success) {
        SendSample(kMetricReadSectorsLongName,
                   read_sectors_per_second,
                   1,
                   kMetricSectorsIOMax,
                   kMetricSectorsBuckets);
        SendSample(kMetricWriteSectorsLongName,
                   write_sectors_per_second,
                   1,
                   kMetricSectorsIOMax,
                   kMetricSectorsBuckets);
        // Reset sector counters.
        read_sectors_ = read_sectors_now;
        write_sectors_ = write_sectors_now;
      }
      if (vmstats_success) {
        SendSample(kMetricPageFaultsLongName,
                   page_faults_per_second,
                   1,
                   kMetricPageFaultsMax,
                   kMetricPageFaultsBuckets);
        SendSample(kMetricSwapInLongName,
                   swap_in_per_second,
                   1,
                   kMetricPageFaultsMax,
                   kMetricPageFaultsBuckets);
        SendSample(kMetricSwapOutLongName,
                   swap_out_per_second,
                   1,
                   kMetricPageFaultsMax,
                   kMetricPageFaultsBuckets);

        vmstats_ = vmstats_now;
      }
      SendCpuThrottleMetrics();
      // Set start time for new cycle.
      stats_initial_time_ = time_now;
      // Schedule short callback.
      stats_state_ = kStatsShort;
      ScheduleStatsCallback(kMetricStatsShortInterval);
      break;
    default:
      LOG(FATAL) << "Invalid stats state";
  }
}

void MetricsDaemon::ScheduleMeminfoCallback(int wait) {
  if (testing_) {
    return;
  }
  base::TimeDelta waitDelta = base::TimeDelta::FromSeconds(wait);
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsDaemon::MeminfoCallback, base::Unretained(this),
                 waitDelta),
      waitDelta);
}

void MetricsDaemon::MeminfoCallback(base::TimeDelta wait) {
  string meminfo_raw;
  const FilePath meminfo_path(kMeminfoFileName);
  if (!base::ReadFileToString(meminfo_path, &meminfo_raw)) {
    LOG(WARNING) << "cannot read " << meminfo_path.value().c_str();
    return;
  }
  // Make both calls even if the first one fails.
  bool success = ProcessMeminfo(meminfo_raw);
  if (ProcessMeminfo(meminfo_raw)) {
    base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
        base::Bind(&MetricsDaemon::MeminfoCallback, base::Unretained(this),
                   wait),
        wait);
  }
}

// static
bool MetricsDaemon::ReadFileToUint64(const base::FilePath& path,
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

bool MetricsDaemon::ReportZram(const base::FilePath& zram_dir) {
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

bool MetricsDaemon::ProcessMeminfo(const string& meminfo_raw) {
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
    SendLinearSample("Platform.MeminfoSwapUsedPercent", swap_used_percent,
                     100, 101);
  }
  return true;
}

bool MetricsDaemon::FillMeminfo(const string& meminfo_raw,
                                vector<MeminfoRecord>* fields) {
  vector<string> lines;
  unsigned int nlines = Tokenize(meminfo_raw, "\n", &lines);

  // Scan meminfo output and collect field values.  Each field name has to
  // match a meminfo entry (case insensitive) after removing non-alpha
  // characters from the entry.
  unsigned int ifield = 0;
  for (unsigned int iline = 0;
       iline < nlines && ifield < fields->size();
       iline++) {
    vector<string> tokens;
    Tokenize(lines[iline], ": ", &tokens);
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

void MetricsDaemon::ScheduleMemuseCallback(double interval) {
  if (testing_) {
    return;
  }
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsDaemon::MemuseCallback, base::Unretained(this)),
      base::TimeDelta::FromSeconds(interval));
}

void MetricsDaemon::MemuseCallback() {
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

bool MetricsDaemon::MemuseCallbackWork() {
  string meminfo_raw;
  const FilePath meminfo_path(kMeminfoFileName);
  if (!base::ReadFileToString(meminfo_path, &meminfo_raw)) {
    LOG(WARNING) << "cannot read " << meminfo_path.value().c_str();
    return false;
  }
  return ProcessMemuse(meminfo_raw);
}

bool MetricsDaemon::ProcessMemuse(const string& meminfo_raw) {
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

void MetricsDaemon::SendSample(const string& name, int sample,
                               int min, int max, int nbuckets) {
  metrics_lib_->SendToUMA(name, sample, min, max, nbuckets);
}

void MetricsDaemon::SendKernelCrashesCumulativeCountStats() {
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
               active_use_seconds / 1000,  // stat is in seconds
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

void MetricsDaemon::SendDailyUseSample(
    const scoped_ptr<PersistentInteger>& use) {
  SendSample(use->Name(),
             use->GetAndClear(),
             1,                        // value of first bucket
             kSecondsPerDay,           // value of last bucket
             50);                      // number of buckets
}

void MetricsDaemon::SendCrashIntervalSample(
    const scoped_ptr<PersistentInteger>& interval) {
  SendSample(interval->Name(),
             interval->GetAndClear(),
             1,                        // value of first bucket
             4 * kSecondsPerWeek,      // value of last bucket
             50);                      // number of buckets
}

void MetricsDaemon::SendCrashFrequencySample(
    const scoped_ptr<PersistentInteger>& frequency) {
  SendSample(frequency->Name(),
             frequency->GetAndClear(),
             1,                        // value of first bucket
             100,                      // value of last bucket
             50);                      // number of buckets
}

void MetricsDaemon::SendLinearSample(const string& name, int sample,
                                     int max, int nbuckets) {
  // TODO(semenzato): add a proper linear histogram to the Chrome external
  // metrics API.
  LOG_IF(FATAL, nbuckets != max + 1) << "unsupported histogram scale";
  metrics_lib_->SendEnumToUMA(name, sample, max);
}

void MetricsDaemon::UpdateStats(TimeTicks now_ticks,
                                Time now_wall_time) {
  const int elapsed_seconds = (now_ticks - last_update_stats_time_).InSeconds();
  daily_active_use_->Add(elapsed_seconds);
  version_cumulative_active_use_->Add(elapsed_seconds);
  user_crash_interval_->Add(elapsed_seconds);
  kernel_crash_interval_->Add(elapsed_seconds);
  version_cumulative_cpu_use_->Add(GetIncrementalCpuUse().InMilliseconds());
  last_update_stats_time_ = now_ticks;

  const TimeDelta since_epoch = now_wall_time - Time::UnixEpoch();
  const int day = since_epoch.InDays();
  const int week = day / 7;

  if (daily_cycle_->Get() != day) {
    daily_cycle_->Set(day);
    SendDailyUseSample(daily_active_use_);
    SendDailyUseSample(version_cumulative_active_use_);
    SendCrashFrequencySample(any_crashes_daily_count_);
    SendCrashFrequencySample(user_crashes_daily_count_);
    SendCrashFrequencySample(kernel_crashes_daily_count_);
    SendCrashFrequencySample(unclean_shutdowns_daily_count_);
    SendKernelCrashesCumulativeCountStats();
  }

  if (weekly_cycle_->Get() != week) {
    weekly_cycle_->Set(week);
    SendCrashFrequencySample(any_crashes_weekly_count_);
    SendCrashFrequencySample(user_crashes_weekly_count_);
    SendCrashFrequencySample(kernel_crashes_weekly_count_);
    SendCrashFrequencySample(unclean_shutdowns_weekly_count_);
  }
}

void MetricsDaemon::HandleUpdateStatsTimeout() {
  UpdateStats(TimeTicks::Now(), Time::Now());
  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&MetricsDaemon::HandleUpdateStatsTimeout,
                 base::Unretained(this)),
      base::TimeDelta::FromMilliseconds(kUpdateStatsIntervalMs));
}
