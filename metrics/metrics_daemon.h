// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_METRICS_DAEMON_H_
#define METRICS_METRICS_DAEMON_H_

#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include <base/files/file_path.h>
#include <base/memory/scoped_ptr.h>
#include <base/time/time.h>
#include <chromeos/daemons/dbus_daemon.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "metrics/metrics_library.h"
#include "metrics/persistent_integer.h"
#include "uploader/upload_service.h"

using chromeos_metrics::PersistentInteger;

class MetricsDaemon : public chromeos::DBusDaemon {
 public:
  MetricsDaemon();
  ~MetricsDaemon();

  // Initializes metrics class variables.
  void Init(bool testing,
            bool uploader_active,
            MetricsLibraryInterface* metrics_lib,
            const std::string& diskstats_path,
            const std::string& vmstats_path,
            const std::string& cpuinfo_max_freq_path,
            const std::string& scaling_max_freq_path,
            const base::TimeDelta& upload_interval,
            const std::string& server,
            const std::string& metrics_file,
            const std::string& config_root);

  // Initializes DBus and MessageLoop variables before running the MessageLoop.
  int OnInit() override;

  // Clean up data set up in OnInit before shutting down message loop.
  void OnShutdown(int* return_code) override;

  // Does all the work.
  int Run() override;

  // Triggers an upload event and exit. (Used to test UploadService)
  void RunUploaderTest();

 protected:
  // Used also by the unit tests.
  static const char kComprDataSizeName[];
  static const char kOrigDataSizeName[];
  static const char kZeroPagesName[];

 private:
  friend class MetricsDaemonTest;
  FRIEND_TEST(MetricsDaemonTest, CheckSystemCrash);
  FRIEND_TEST(MetricsDaemonTest, ComputeEpochNoCurrent);
  FRIEND_TEST(MetricsDaemonTest, ComputeEpochNoLast);
  FRIEND_TEST(MetricsDaemonTest, GetHistogramPath);
  FRIEND_TEST(MetricsDaemonTest, IsNewEpoch);
  FRIEND_TEST(MetricsDaemonTest, MessageFilter);
  FRIEND_TEST(MetricsDaemonTest, ParseVmStats);
  FRIEND_TEST(MetricsDaemonTest, ProcessKernelCrash);
  FRIEND_TEST(MetricsDaemonTest, ProcessMeminfo);
  FRIEND_TEST(MetricsDaemonTest, ProcessMeminfo2);
  FRIEND_TEST(MetricsDaemonTest, ProcessUncleanShutdown);
  FRIEND_TEST(MetricsDaemonTest, ProcessUserCrash);
  FRIEND_TEST(MetricsDaemonTest, ReportCrashesDailyFrequency);
  FRIEND_TEST(MetricsDaemonTest, ReadFreqToInt);
  FRIEND_TEST(MetricsDaemonTest, ReportDailyUse);
  FRIEND_TEST(MetricsDaemonTest, ReportDiskStats);
  FRIEND_TEST(MetricsDaemonTest, ReportKernelCrashInterval);
  FRIEND_TEST(MetricsDaemonTest, ReportUncleanShutdownInterval);
  FRIEND_TEST(MetricsDaemonTest, ReportUserCrashInterval);
  FRIEND_TEST(MetricsDaemonTest, SendSample);
  FRIEND_TEST(MetricsDaemonTest, SendCpuThrottleMetrics);
  FRIEND_TEST(MetricsDaemonTest, SendZramMetrics);

  // State for disk stats collector callback.
  enum StatsState {
    kStatsShort,    // short wait before short interval collection
    kStatsLong,     // final wait before new collection
  };

  // Data record for aggregating daily usage.
  class UseRecord {
   public:
    UseRecord() : day_(0), seconds_(0) {}
    int day_;
    int seconds_;
  };

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

  // Record for retrieving and reporting values from /proc/vmstat
  struct VmstatRecord {
    uint64_t page_faults_;    // major faults
    uint64_t swap_in_;        // pages swapped in
    uint64_t swap_out_;       // pages swapped out
  };

  // Metric parameters.
  static const char kMetricReadSectorsLongName[];
  static const char kMetricReadSectorsShortName[];
  static const char kMetricWriteSectorsLongName[];
  static const char kMetricWriteSectorsShortName[];
  static const char kMetricPageFaultsShortName[];
  static const char kMetricPageFaultsLongName[];
  static const char kMetricSwapInLongName[];
  static const char kMetricSwapInShortName[];
  static const char kMetricSwapOutLongName[];
  static const char kMetricSwapOutShortName[];
  static const char kMetricScaledCpuFrequencyName[];
  static const int kMetricStatsShortInterval;
  static const int kMetricStatsLongInterval;
  static const int kMetricMeminfoInterval;
  static const int kMetricSectorsIOMax;
  static const int kMetricSectorsBuckets;
  static const int kMetricPageFaultsMax;
  static const int kMetricPageFaultsBuckets;
  static const char kMetricsDiskStatsPath[];
  static const char kMetricsVmStatsPath[];
  static const char kMetricsProcStatFileName[];
  static const int kMetricsProcStatFirstLineItemsCount;

  // Returns the active time since boot (uptime minus sleep time) in seconds.
  double GetActiveTime();

  // D-Bus filter callback.
  static DBusHandlerResult MessageFilter(DBusConnection* connection,
                                         DBusMessage* message,
                                         void* user_data);

  // Updates the daily usage file, if necessary, by adding |seconds|
  // of active use to the |day| since Epoch. If there's usage data for
  // day in the past in the usage file, that data is sent to UMA and
  // removed from the file. If there's already usage data for |day| in
  // the usage file, the |seconds| are accumulated.
  void LogDailyUseRecord(int day, int seconds);

  // Updates the active use time and logs time between user-space
  // process crashes.
  void ProcessUserCrash();

  // Updates the active use time and logs time between kernel crashes.
  void ProcessKernelCrash();

  // Updates the active use time and logs time between unclean shutdowns.
  void ProcessUncleanShutdown();

  // Checks if a kernel crash has been detected and returns true if
  // so.  The method assumes that a kernel crash has happened if
  // |crash_file| exists.  It removes the file immediately if it
  // exists, so it must not be called more than once.
  bool CheckSystemCrash(const std::string& crash_file);

  // Report daily use through UMA.
  void ReportDailyUse(int use_seconds);

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

  // Returns the total (system-wide) CPU usage between the time of the most
  // recent call to this function and now.
  base::TimeDelta GetIncrementalCpuUse();

  // Sends a sample representing the number of seconds of active use
  // for a 24-hour period.
  void SendDailyUseSample(const scoped_ptr<PersistentInteger>& use);

  // Sends a sample representing a time interval between two crashes of the
  // same type.
  void SendCrashIntervalSample(const scoped_ptr<PersistentInteger>& interval);

  // Sends a sample representing a frequency of crashes of some type.
  void SendCrashFrequencySample(const scoped_ptr<PersistentInteger>& frequency);

  // Initializes vm and disk stats reporting.
  void StatsReporterInit();

  // Schedules a callback for the next vm and disk stats collection.
  void ScheduleStatsCallback(int wait);

  // Reads cumulative disk statistics from sysfs.  Returns true for success.
  bool DiskStatsReadStats(uint64_t* read_sectors, uint64_t* write_sectors);

  // Reads cumulative vm statistics from procfs.  Returns true for success.
  bool VmStatsReadStats(struct VmstatRecord* stats);

  // Parse cumulative vm statistics from a C string.  Returns true for success.
  bool VmStatsParseStats(const char* stats, struct VmstatRecord* record);

  // Reports disk and vm statistics.
  void StatsCallback();

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

  // Sends stats for thermal CPU throttling.
  void SendCpuThrottleMetrics();

  // Reads an integer CPU frequency value from sysfs.
  bool ReadFreqToInt(const std::string& sysfs_file_name, int* value);

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

  // VARIABLES

  // Test mode.
  bool testing_;

  // Whether the uploader is enabled or disabled.
  bool uploader_active_;

  // Root of the configuration files to use.
  std::string config_root_;

  // The metrics library handle.
  MetricsLibraryInterface* metrics_lib_;

  // Timestamps last network state update.  This timestamp is used to
  // sample the time from the network going online to going offline so
  // TimeTicks ensures a monotonically increasing TimeDelta.
  base::TimeTicks network_state_last_;

  // The last time that UpdateStats() was called.
  base::TimeTicks last_update_stats_time_;

  // End time of current memuse stat collection interval.
  double memuse_final_time_;

  // Selects the wait time for the next memory use callback.
  unsigned int memuse_interval_index_;

  // Contain the most recent disk and vm cumulative stats.
  uint64_t read_sectors_;
  uint64_t write_sectors_;
  struct VmstatRecord vmstats_;

  StatsState stats_state_;
  double stats_initial_time_;

  // The system "HZ", or frequency of ticks.  Some system data uses ticks as a
  // unit, and this is used to convert to standard time units.
  uint32_t ticks_per_second_;
  // Used internally by GetIncrementalCpuUse() to return the CPU utilization
  // between calls.
  uint64_t latest_cpu_use_ticks_;

  // Persistent values and accumulators for crash statistics.
  scoped_ptr<PersistentInteger> daily_cycle_;
  scoped_ptr<PersistentInteger> weekly_cycle_;
  scoped_ptr<PersistentInteger> version_cycle_;

  // Active use accumulated in a day.
  scoped_ptr<PersistentInteger> daily_active_use_;
  // Active use accumulated since the latest version update.
  scoped_ptr<PersistentInteger> version_cumulative_active_use_;

  // The CPU time accumulator.  This contains the CPU time, in milliseconds,
  // used by the system since the most recent OS version update.
  scoped_ptr<PersistentInteger> version_cumulative_cpu_use_;

  scoped_ptr<PersistentInteger> user_crash_interval_;
  scoped_ptr<PersistentInteger> kernel_crash_interval_;
  scoped_ptr<PersistentInteger> unclean_shutdown_interval_;

  scoped_ptr<PersistentInteger> any_crashes_daily_count_;
  scoped_ptr<PersistentInteger> any_crashes_weekly_count_;
  scoped_ptr<PersistentInteger> user_crashes_daily_count_;
  scoped_ptr<PersistentInteger> user_crashes_weekly_count_;
  scoped_ptr<PersistentInteger> kernel_crashes_daily_count_;
  scoped_ptr<PersistentInteger> kernel_crashes_weekly_count_;
  scoped_ptr<PersistentInteger> kernel_crashes_version_count_;
  scoped_ptr<PersistentInteger> unclean_shutdowns_daily_count_;
  scoped_ptr<PersistentInteger> unclean_shutdowns_weekly_count_;

  std::string diskstats_path_;
  std::string vmstats_path_;
  std::string scaling_max_freq_path_;
  std::string cpuinfo_max_freq_path_;

  base::TimeDelta upload_interval_;
  std::string server_;
  std::string metrics_file_;

  scoped_ptr<UploadService> upload_service_;
};

#endif  // METRICS_METRICS_DAEMON_H_
