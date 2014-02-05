// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_DAEMON_H_
#define METRICS_DAEMON_H_

#include <dbus/dbus.h>
#include <glib.h>
#include <map>

#include <base/files/file_path.h>
#include <base/memory/scoped_ptr.h>
#include <base/time/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "metrics_library.h"

namespace chromeos_metrics {
class FrequencyCounter;
class VersionCounter;
class TaggedCounter;
class TaggedCounterReporter;
}

class MetricsDaemon {

 public:
  MetricsDaemon();
  ~MetricsDaemon();

  // Initializes.
  void Init(bool testing, MetricsLibraryInterface* metrics_lib,
            const std::string& diskstats_path,
            const std::string& vmstats_path,
            const std::string& cpuinfo_max_freq_path,
            const std::string& scaling_max_freq_path);

  // Does all the work. If |run_as_daemon| is true, daemonizes by
  // forking.
  void Run(bool run_as_daemon);

 private:
  friend class MetricsDaemonTest;
  FRIEND_TEST(MetricsDaemonTest, CheckSystemCrash);
  FRIEND_TEST(MetricsDaemonTest, ComputeEpochNoCurrent);
  FRIEND_TEST(MetricsDaemonTest, ComputeEpochNoLast);
  FRIEND_TEST(MetricsDaemonTest, GetHistogramPath);
  FRIEND_TEST(MetricsDaemonTest, IsNewEpoch);
  FRIEND_TEST(MetricsDaemonTest, LookupPowerState);
  FRIEND_TEST(MetricsDaemonTest, LookupScreenSaverState);
  FRIEND_TEST(MetricsDaemonTest, LookupSessionState);
  FRIEND_TEST(MetricsDaemonTest, MessageFilter);
  FRIEND_TEST(MetricsDaemonTest, ParseVmStats);
  FRIEND_TEST(MetricsDaemonTest, PowerStateChanged);
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
  FRIEND_TEST(MetricsDaemonTest, ScreenSaverStateChanged);
  FRIEND_TEST(MetricsDaemonTest, SendMetric);
  FRIEND_TEST(MetricsDaemonTest, SendCpuThrottleMetrics);
  FRIEND_TEST(MetricsDaemonTest, SessionStateChanged);
  FRIEND_TEST(MetricsDaemonTest, SetUserActiveState);
  FRIEND_TEST(MetricsDaemonTest, SetUserActiveStateTimeJump);

  // The power states (see power_states.h).
  enum PowerState {
    kUnknownPowerState = -1, // Initial/unknown power state.
#define STATE(name, capname) kPowerState ## capname,
#include "power_states.h"
    kNumberPowerStates
  };

  // The user session states (see session_states.h).
  enum SessionState {
    kUnknownSessionState = -1, // Initial/unknown user session state.
#define STATE(name, capname) kSessionState ## capname,
#include "session_states.h"
    kNumberSessionStates
  };

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

  typedef std::map<std::string, chromeos_metrics::FrequencyCounter*>
    FrequencyCounters;

  // Metric parameters.
  static const char kMetricAnyCrashesDailyName[];
  static const char kMetricAnyCrashesWeeklyName[];
  static const int  kMetricCrashFrequencyBuckets;
  static const int  kMetricCrashFrequencyMax;
  static const int  kMetricCrashFrequencyMin;
  static const int  kMetricCrashIntervalBuckets;
  static const int  kMetricCrashIntervalMax;
  static const int  kMetricCrashIntervalMin;
  static const int  kMetricCumulativeCrashCountBuckets;
  static const int  kMetricCumulativeCrashCountMax;
  static const int  kMetricCumulativeCrashCountMin;
  static const int  kMetricDailyUseTimeBuckets;
  static const int  kMetricDailyUseTimeMax;
  static const int  kMetricDailyUseTimeMin;
  static const char kMetricDailyUseTimeName[];
  static const char kMetricKernelCrashesDailyName[];
  static const char kMetricKernelCrashesWeeklyName[];
  static const char kMetricKernelCrashesVersionName[];
  static const char kMetricKernelCrashIntervalName[];
  static const char kMetricsPath[];
  static const char kLsbReleasePath[];
  static const char kMetricUncleanShutdownIntervalName[];
  static const char kMetricUncleanShutdownsDailyName[];
  static const char kMetricUncleanShutdownsWeeklyName[];
  static const char kMetricUserCrashesDailyName[];
  static const char kMetricUserCrashesWeeklyName[];
  static const char kMetricUserCrashIntervalName[];
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

  // Array of power states.
  static const char* kPowerStates_[kNumberPowerStates];

  // Array of user session states.
  static const char* kSessionStates_[kNumberSessionStates];

  // Returns the active time since boot (uptime minus sleep time) in seconds.
  double GetActiveTime();

  // Clears and deletes the data contained in frequency_counters_.
  void DeleteFrequencyCounters();

  // Configures the given crash interval reporter.
  void ConfigureCrashIntervalReporter(
      const char* histogram_name,
      scoped_ptr<chromeos_metrics::TaggedCounterReporter>* reporter);

  // Configures the given frequency counter reporter.
  void ConfigureCrashFrequencyReporter(const char* histogram_name);

  // Configures the given version counter reporter.
  void ConfigureCrashVersionReporter(const char* histogram_name);

  // Returns file path to persistent file for generating given histogram.
  base::FilePath GetHistogramPath(const char* histogram_name);

  // Creates the event loop and enters it.
  void Loop();

  // D-Bus filter callback.
  static DBusHandlerResult MessageFilter(DBusConnection* connection,
                                         DBusMessage* message,
                                         void* user_data);

  // Processes power state change.
  void PowerStateChanged(const char* state_name, base::Time now);

  // Given the state name, returns the state id.
  PowerState LookupPowerState(const char* state_name);

  // Processes user session state change.
  void SessionStateChanged(const char* state_name, base::Time now);

  // Given the state name, returns the state id.
  SessionState LookupSessionState(const char* state_name);

  // Updates the user-active state to |active| and logs the usage data
  // since the last update. If the user has just become active,
  // reschedule the daily use monitor for more frequent updates --
  // this is followed by an exponential back-off (see UseMonitor).
  // While in active use, this method should be called at intervals no
  // longer than kUseMonitorIntervalMax otherwise new use time will be
  // discarded.
  void SetUserActiveState(bool active, base::Time now);

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

  // Callbacks for the daily use monitor. The daily use monitor uses
  // LogDailyUseRecord to aggregate current usage data and send it to
  // UMA, if necessary. It also reschedules itself using an
  // exponentially bigger interval (up to a certain maximum) -- so
  // usage is monitored less frequently with longer active use.
  static gboolean UseMonitorStatic(gpointer data);
  bool UseMonitor();

  // Schedules or reschedules a daily use monitor for |interval|
  // seconds from now. |backoff| mode is used by the use monitor to
  // reschedule itself. If there's a monitor scheduled already and
  // |backoff| is false, unschedules it first. Doesn't schedule a
  // monitor for more than kUseMonitorIntervalMax seconds in the
  // future (see metrics_daemon.cc). Returns true if a new use monitor
  // was scheduled, false otherwise (note that if |backoff| is false a
  // new use monitor will always be scheduled).
  bool ScheduleUseMonitor(int interval, bool backoff);

  // Unschedules a scheduled use monitor, if any.
  void UnscheduleUseMonitor();

  // Report daily use through UMA.
  static void ReportDailyUse(void* handle, int count);

  // Sends a regular (exponential) histogram sample to Chrome for
  // transport to UMA. See MetricsLibrary::SendToUMA in
  // metrics_library.h for a description of the arguments.
  void SendMetric(const std::string& name, int sample,
                  int min, int max, int nbuckets);

  // Sends a linear histogram sample to Chrome for transport to UMA. See
  // MetricsLibrary::SendToUMA in metrics_library.h for a description of the
  // arguments.
  void SendLinearMetric(const std::string& name, int sample,
                        int max, int nbuckets);

  // Initializes vm and disk stats reporting.
  void StatsReporterInit();

  // Schedules a callback for the next vm and disk stats collection.
  void ScheduleStatsCallback(int wait);

  // Reads cumulative disk statistics from sysfs.  Returns true for success.
  bool DiskStatsReadStats(long int* read_sectors, long int* write_sectors);

  // Reads cumulative vm statistics from procfs.  Returns true for success.
  bool VmStatsReadStats(struct VmstatRecord* stats);

  // Parse cumulative vm statistics from a C string.  Returns true for success.
  bool VmStatsParseStats(const char* stats, struct VmstatRecord* record);

  // Reports disk and vm statistics (static version for glib).  Arguments are a
  // glib artifact.
  static gboolean StatsCallbackStatic(void* handle);

  // Reports disk and vm statistics.
  void StatsCallback();

  // Schedules meminfo collection callback.
  void ScheduleMeminfoCallback(int wait);

  // Reports memory statistics (static version for glib).  Argument is a glib
  // artifact.
  static gboolean MeminfoCallbackStatic(void* handle);

  // Reports memory statistics.  Returns false on failure.
  bool MeminfoCallback();

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

  // Static wrapper for MemuseCallback.  Always returns false.
  static gboolean MemuseCallbackStatic(void* handle);

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
  uint32 GetOsVersionHash();

  // Test mode.
  bool testing_;

  // The metrics library handle.
  MetricsLibraryInterface* metrics_lib_;

  // Timestamps last network state update.  This timestamp is used to
  // sample the time from the network going online to going offline so
  // TimeTicks ensures a monotonically increasing TimeDelta.
  base::TimeTicks network_state_last_;

  // Current power state.
  PowerState power_state_;

  // Current user session state.
  SessionState session_state_;

  // Is the user currently active: power is on, user session has
  // started, screen is not locked.
  bool user_active_;

  // Timestamps last user active update. Active use time is aggregated
  // each day before sending to UMA so using time since the epoch as
  // the timestamp.
  base::Time user_active_last_;

  // Daily active use time in seconds.
  scoped_ptr<chromeos_metrics::TaggedCounter> daily_use_;

  // Active use time between user-space process crashes.
  scoped_ptr<chromeos_metrics::TaggedCounterReporter> user_crash_interval_;

  // Active use time between kernel crashes.
  scoped_ptr<chromeos_metrics::TaggedCounterReporter> kernel_crash_interval_;

  // Active use time between unclean shutdowns crashes.
  scoped_ptr<chromeos_metrics::TaggedCounterReporter>
      unclean_shutdown_interval_;

  // Map of all frequency counters, to simplify flushing them.
  FrequencyCounters frequency_counters_;

  // This contains a cumulative number of kernel crashes since the latest
  // version update.
  chromeos_metrics::VersionCounter* kernel_crash_version_counter_;

  // Sleep period until the next daily usage aggregation performed by
  // the daily use monitor (see ScheduleUseMonitor).
  int usemon_interval_;

  // Scheduled daily use monitor source (see ScheduleUseMonitor).
  GSource* usemon_source_;

  // End time of current memuse stat collection interval.
  double memuse_final_time_;

  // Selects the wait time for the next memory use callback.
  unsigned int memuse_interval_index_;

  // Contain the most recent disk and vm cumulative stats.
  long int read_sectors_;
  long int write_sectors_;
  struct VmstatRecord vmstats_;

  StatsState stats_state_;
  double stats_initial_time_;

  std::string diskstats_path_;
  std::string vmstats_path_;
  std::string scaling_max_freq_path_;
  std::string cpuinfo_max_freq_path_;
};

#endif  // METRICS_DAEMON_H_
