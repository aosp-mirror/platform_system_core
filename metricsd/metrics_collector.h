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

#ifndef METRICS_METRICS_COLLECTOR_H_
#define METRICS_METRICS_COLLECTOR_H_

#include <stdint.h>

#include <map>
#include <memory>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/weak_ptr.h>
#include <base/time/time.h>
#include <brillo/binder_watcher.h>
#include <brillo/daemons/daemon.h>
#include <libweaved/command.h>
#include <libweaved/service.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "collectors/averaged_statistics_collector.h"
#include "collectors/cpu_usage_collector.h"
#include "collectors/disk_usage_collector.h"
#include "metrics/metrics_library.h"
#include "persistent_integer.h"

using chromeos_metrics::PersistentInteger;
using std::unique_ptr;

class MetricsCollector : public brillo::Daemon {
 public:
  MetricsCollector();
  ~MetricsCollector();

  // Initializes metrics class variables.
  void Init(bool testing,
            MetricsLibraryInterface* metrics_lib,
            const std::string& diskstats_path,
            const base::FilePath& private_metrics_directory,
            const base::FilePath& shared_metrics_directory);

  // Initializes the daemon.
  int OnInit() override;

  // Does all the work.
  int Run() override;

  // Returns the active time since boot (uptime minus sleep time) in seconds.
  static double GetActiveTime();

  // Updates the active use time and logs time between user-space
  // process crashes.  Called via MetricsCollectorServiceTrampoline.
  void ProcessUserCrash();

 protected:
  // Used also by the unit tests.
  static const char kComprDataSizeName[];
  static const char kOrigDataSizeName[];
  static const char kZeroPagesName[];

 private:
  friend class MetricsCollectorTest;
  FRIEND_TEST(MetricsCollectorTest, CheckSystemCrash);
  FRIEND_TEST(MetricsCollectorTest, ComputeEpochNoCurrent);
  FRIEND_TEST(MetricsCollectorTest, ComputeEpochNoLast);
  FRIEND_TEST(MetricsCollectorTest, GetHistogramPath);
  FRIEND_TEST(MetricsCollectorTest, IsNewEpoch);
  FRIEND_TEST(MetricsCollectorTest, MessageFilter);
  FRIEND_TEST(MetricsCollectorTest, ProcessKernelCrash);
  FRIEND_TEST(MetricsCollectorTest, ProcessMeminfo);
  FRIEND_TEST(MetricsCollectorTest, ProcessMeminfo2);
  FRIEND_TEST(MetricsCollectorTest, ProcessUncleanShutdown);
  FRIEND_TEST(MetricsCollectorTest, ProcessUserCrash);
  FRIEND_TEST(MetricsCollectorTest, ReportCrashesDailyFrequency);
  FRIEND_TEST(MetricsCollectorTest, ReportKernelCrashInterval);
  FRIEND_TEST(MetricsCollectorTest, ReportUncleanShutdownInterval);
  FRIEND_TEST(MetricsCollectorTest, ReportUserCrashInterval);
  FRIEND_TEST(MetricsCollectorTest, SendSample);
  FRIEND_TEST(MetricsCollectorTest, SendZramMetrics);

  // Type of scale to use for meminfo histograms.  For most of them we use
  // percent of total RAM, but for some we use absolute numbers, usually in
  // megabytes, on a log scale from 0 to 4000, and 0 to 8000 for compressed
  // swap (since it can be larger than total RAM).
  enum MeminfoOp {
    kMeminfoOp_HistPercent = 0,
    kMeminfoOp_HistLog,
    kMeminfoOp_SwapTotal,
    kMeminfoOp_SwapFree,
  };

  // Record for retrieving and reporting values from /proc/meminfo.
  struct MeminfoRecord {
    const char* name;        // print name
    const char* match;       // string to match in output of /proc/meminfo
    MeminfoOp op;            // histogram scale selector, or other operator
    int value;               // value from /proc/meminfo
  };

  // Enables metrics reporting.
  void OnEnableMetrics(std::unique_ptr<weaved::Command> command);

  // Disables metrics reporting.
  void OnDisableMetrics(std::unique_ptr<weaved::Command> command);

  // Updates the weave device state.
  void UpdateWeaveState();

  // Updates the active use time and logs time between kernel crashes.
  void ProcessKernelCrash();

  // Updates the active use time and logs time between unclean shutdowns.
  void ProcessUncleanShutdown();

  // Checks if a kernel crash has been detected and returns true if
  // so.  The method assumes that a kernel crash has happened if
  // |crash_file| exists.  It removes the file immediately if it
  // exists, so it must not be called more than once.
  bool CheckSystemCrash(const std::string& crash_file);

  // Sends a regular (exponential) histogram sample to Chrome for
  // transport to UMA. See MetricsLibrary::SendToUMA in
  // metrics_library.h for a description of the arguments.
  void SendSample(const std::string& name, int sample,
                  int min, int max, int nbuckets);

  // Sends a linear histogram sample to Chrome for transport to UMA. See
  // MetricsLibrary::SendToUMA in metrics_library.h for a description of the
  // arguments.
  void SendLinearSample(const std::string& name, int sample,
                        int max, int nbuckets);

  // Sends various cumulative kernel crash-related stats, for instance the
  // total number of kernel crashes since the last version update.
  void SendKernelCrashesCumulativeCountStats();

  // Sends a sample representing the number of seconds of active use
  // for a 24-hour period and reset |use|.
  void SendAndResetDailyUseSample(const unique_ptr<PersistentInteger>& use);

  // Sends a sample representing a time interval between two crashes of the
  // same type and reset |interval|.
  void SendAndResetCrashIntervalSample(
      const unique_ptr<PersistentInteger>& interval);

  // Sends a sample representing a frequency of crashes of some type and reset
  // |frequency|.
  void SendAndResetCrashFrequencySample(
      const unique_ptr<PersistentInteger>& frequency);

  // Initializes vm and disk stats reporting.
  void StatsReporterInit();

  // Schedules meminfo collection callback.
  void ScheduleMeminfoCallback(int wait);

  // Reports memory statistics.  Reschedules callback on success.
  void MeminfoCallback(base::TimeDelta wait);

  // Parses content of /proc/meminfo and sends fields of interest to UMA.
  // Returns false on errors.  |meminfo_raw| contains the content of
  // /proc/meminfo.
  bool ProcessMeminfo(const std::string& meminfo_raw);

  // Parses meminfo data from |meminfo_raw|.  |fields| is a vector containing
  // the fields of interest.  The order of the fields must be the same in which
  // /proc/meminfo prints them.  The result of parsing fields[i] is placed in
  // fields[i].value.
  bool FillMeminfo(const std::string& meminfo_raw,
                   std::vector<MeminfoRecord>* fields);

  // Schedule a memory use callback in |interval| seconds.
  void ScheduleMemuseCallback(double interval);

  // Calls MemuseCallbackWork, and possibly schedules next callback, if enough
  // active time has passed.  Otherwise reschedules itself to simulate active
  // time callbacks (i.e. wall clock time minus sleep time).
  void MemuseCallback();

  // Reads /proc/meminfo and sends total anonymous memory usage to UMA.
  bool MemuseCallbackWork();

  // Parses meminfo data and sends it to UMA.
  bool ProcessMemuse(const std::string& meminfo_raw);

  // Reads the current OS version from /etc/lsb-release and hashes it
  // to a unsigned 32-bit int.
  uint32_t GetOsVersionHash();

  // Updates stats, additionally sending them to UMA if enough time has elapsed
  // since the last report.
  void UpdateStats(base::TimeTicks now_ticks, base::Time now_wall_time);

  // Invoked periodically by |update_stats_timeout_id_| to call UpdateStats().
  void HandleUpdateStatsTimeout();

  // Reports zram statistics.
  bool ReportZram(const base::FilePath& zram_dir);

  // Reads a string from a file and converts it to uint64_t.
  static bool ReadFileToUint64(const base::FilePath& path, uint64_t* value);

  // Callback invoked when a connection to weaved's service is established
  // over Binder interface.
  void OnWeaveServiceConnected(const std::weak_ptr<weaved::Service>& service);

  // VARIABLES

  // Test mode.
  bool testing_;

  // Publicly readable metrics directory.
  base::FilePath shared_metrics_directory_;

  // The metrics library handle.
  MetricsLibraryInterface* metrics_lib_;

  // The last time that UpdateStats() was called.
  base::TimeTicks last_update_stats_time_;

  // End time of current memuse stat collection interval.
  double memuse_final_time_;

  // Selects the wait time for the next memory use callback.
  unsigned int memuse_interval_index_;

  // Used internally by GetIncrementalCpuUse() to return the CPU utilization
  // between calls.
  base::TimeDelta latest_cpu_use_microseconds_;

  // Persistent values and accumulators for crash statistics.
  unique_ptr<PersistentInteger> daily_cycle_;
  unique_ptr<PersistentInteger> weekly_cycle_;
  unique_ptr<PersistentInteger> version_cycle_;

  // Active use accumulated in a day.
  unique_ptr<PersistentInteger> daily_active_use_;
  // Active use accumulated since the latest version update.
  unique_ptr<PersistentInteger> version_cumulative_active_use_;

  // The CPU time accumulator.  This contains the CPU time, in milliseconds,
  // used by the system since the most recent OS version update.
  unique_ptr<PersistentInteger> version_cumulative_cpu_use_;

  unique_ptr<PersistentInteger> user_crash_interval_;
  unique_ptr<PersistentInteger> kernel_crash_interval_;
  unique_ptr<PersistentInteger> unclean_shutdown_interval_;

  unique_ptr<PersistentInteger> any_crashes_daily_count_;
  unique_ptr<PersistentInteger> any_crashes_weekly_count_;
  unique_ptr<PersistentInteger> user_crashes_daily_count_;
  unique_ptr<PersistentInteger> user_crashes_weekly_count_;
  unique_ptr<PersistentInteger> kernel_crashes_daily_count_;
  unique_ptr<PersistentInteger> kernel_crashes_weekly_count_;
  unique_ptr<PersistentInteger> kernel_crashes_version_count_;
  unique_ptr<PersistentInteger> unclean_shutdowns_daily_count_;
  unique_ptr<PersistentInteger> unclean_shutdowns_weekly_count_;

  unique_ptr<CpuUsageCollector> cpu_usage_collector_;
  unique_ptr<DiskUsageCollector> disk_usage_collector_;
  unique_ptr<AveragedStatisticsCollector> averaged_stats_collector_;

  unique_ptr<weaved::Service::Subscription> weave_service_subscription_;
  std::weak_ptr<weaved::Service> service_;

  base::WeakPtrFactory<MetricsCollector> weak_ptr_factory_{this};
};

#endif  // METRICS_METRICS_COLLECTOR_H_
