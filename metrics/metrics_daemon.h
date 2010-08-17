// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_DAEMON_H_
#define METRICS_DAEMON_H_

#include <dbus/dbus.h>
#include <glib.h>

#include <base/scoped_ptr.h>
#include <base/time.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "metrics_library.h"

namespace chromeos_metrics {
class FrequencyCounter;
class TaggedCounterInterface;
}

class MetricsDaemon {

 public:
  MetricsDaemon();
  ~MetricsDaemon();

  // Initializes.
  void Init(bool testing, MetricsLibraryInterface* metrics_lib);

  // Does all the work. If |run_as_daemon| is true, daemonizes by
  // forking.
  void Run(bool run_as_daemon);

 private:
  friend class MetricsDaemonTest;
  FRIEND_TEST(MetricsDaemonTest, CheckSystemCrash);
  FRIEND_TEST(MetricsDaemonTest, LookupNetworkState);
  FRIEND_TEST(MetricsDaemonTest, LookupPowerState);
  FRIEND_TEST(MetricsDaemonTest, LookupScreenSaverState);
  FRIEND_TEST(MetricsDaemonTest, LookupSessionState);
  FRIEND_TEST(MetricsDaemonTest, MessageFilter);
  FRIEND_TEST(MetricsDaemonTest, NetStateChangedSimpleDrop);
  FRIEND_TEST(MetricsDaemonTest, NetStateChangedSuspend);
  FRIEND_TEST(MetricsDaemonTest, PowerStateChanged);
  FRIEND_TEST(MetricsDaemonTest, ProcessKernelCrash);
  FRIEND_TEST(MetricsDaemonTest, ProcessUncleanShutdown);
  FRIEND_TEST(MetricsDaemonTest, ProcessUserCrash);
  FRIEND_TEST(MetricsDaemonTest, ReportCrashesDailyFrequency);
  FRIEND_TEST(MetricsDaemonTest, ReportDailyUse);
  FRIEND_TEST(MetricsDaemonTest, ReportKernelCrashInterval);
  FRIEND_TEST(MetricsDaemonTest, ReportUncleanShutdownInterval);
  FRIEND_TEST(MetricsDaemonTest, ReportUserCrashInterval);
  FRIEND_TEST(MetricsDaemonTest, ScreenSaverStateChanged);
  FRIEND_TEST(MetricsDaemonTest, SendMetric);
  FRIEND_TEST(MetricsDaemonTest, SessionStateChanged);
  FRIEND_TEST(MetricsDaemonTest, SetUserActiveState);
  FRIEND_TEST(MetricsDaemonTest, SetUserActiveStateTimeJump);

  // The network states (see network_states.h).
  enum NetworkState {
    kUnknownNetworkState = -1, // Initial/unknown network state.
#define STATE(name, capname) kNetworkState ## capname,
#include "network_states.h"
    kNumberNetworkStates
  };

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

  // Data record for aggregating daily usage.
  class UseRecord {
   public:
    UseRecord() : day_(0), seconds_(0) {}
    int day_;
    int seconds_;
  };

  // Metric parameters.
  static const char kMetricAnyCrashesDailyName[];
  static const char kMetricCrashesDailyBuckets;
  static const char kMetricCrashesDailyMax;
  static const char kMetricCrashesDailyMin;
  static const int  kMetricCrashIntervalBuckets;
  static const int  kMetricCrashIntervalMax;
  static const int  kMetricCrashIntervalMin;
  static const int  kMetricDailyUseTimeBuckets;
  static const int  kMetricDailyUseTimeMax;
  static const int  kMetricDailyUseTimeMin;
  static const char kMetricDailyUseTimeName[];
  static const char kMetricKernelCrashesDailyName[];
  static const char kMetricKernelCrashIntervalName[];
  static const int  kMetricTimeToNetworkDropBuckets;
  static const int  kMetricTimeToNetworkDropMax;
  static const int  kMetricTimeToNetworkDropMin;
  static const char kMetricTimeToNetworkDropName[];
  static const char kMetricUncleanShutdownIntervalName[];
  static const char kMetricUncleanShutdownsDailyName[];
  static const char kMetricUserCrashesDailyName[];
  static const char kMetricUserCrashIntervalName[];

  // D-Bus message match strings.
  static const char* kDBusMatches_[];

  // Array of network states.
  static const char* kNetworkStates_[kNumberNetworkStates];

  // Array of power states.
  static const char* kPowerStates_[kNumberPowerStates];

  // Array of user session states.
  static const char* kSessionStates_[kNumberSessionStates];

  // Creates the event loop and enters it.
  void Loop();

  // D-Bus filter callback.
  static DBusHandlerResult MessageFilter(DBusConnection* connection,
                                         DBusMessage* message,
                                         void* user_data);

  // Processes network state change.
  void NetStateChanged(const char* state_name, base::TimeTicks ticks);

  // Given the state name, returns the state id.
  NetworkState LookupNetworkState(const char* state_name);

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

  // Sends a regular (exponential) histogram sample to Chrome for
  // transport to UMA. See MetricsLibrary::SendToUMA in
  // metrics_library.h for a description of the arguments.
  void SendMetric(const std::string& name, int sample,
                  int min, int max, int nbuckets);

  // TaggedCounter callback to process aggregated daily usage data and
  // send to UMA.
  static void ReportDailyUse(void* data, int tag, int count);

  // Helper to report a crash interval to UMA.
  static void ReportCrashInterval(const char* histogram_name,
                                  void* handle, int count);

  // TaggedCounter callback to process time between user-space process
  // crashes and send to UMA.
  static void ReportUserCrashInterval(void* data, int tag, int count);

  // TaggedCounter callback to process time between kernel crashes and
  // send to UMA.
  static void ReportKernelCrashInterval(void* data, int tag, int count);

  // TaggedCounter callback to process time between unclean shutdowns and
  // send to UMA.
  static void ReportUncleanShutdownInterval(void* data, int tag, int count);

  // Helper to report a daily crash frequency to UMA.
  static void ReportCrashesDailyFrequency(const char* histogram_name,
                                          void* handle, int count);

  // TaggedCounter callback to report daily crash frequency to UMA.
  static void ReportUserCrashesDaily(void* handle, int tag, int count);

  // TaggedCounter callback to report kernel crash frequency to UMA.
  static void ReportKernelCrashesDaily(void* handle, int tag, int count);

  // TaggedCounter callback to report unclean shutdown frequency to UMA.
  static void ReportUncleanShutdownsDaily(void* handle, int tag, int count);

  // TaggedCounter callback to report frequency of any crashes to UMA.
  static void ReportAnyCrashesDaily(void* handle, int tag, int count);

  // Test mode.
  bool testing_;

  // The metrics library handle.
  MetricsLibraryInterface* metrics_lib_;

  // Current network state.
  NetworkState network_state_;

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
  scoped_ptr<chromeos_metrics::TaggedCounterInterface> daily_use_;

  // Active use time between user-space process crashes.
  scoped_ptr<chromeos_metrics::TaggedCounterInterface> user_crash_interval_;

  // Active use time between kernel crashes.
  scoped_ptr<chromeos_metrics::TaggedCounterInterface> kernel_crash_interval_;

  // Active use time between unclean shutdowns crashes.
  scoped_ptr<chromeos_metrics::TaggedCounterInterface>
      unclean_shutdown_interval_;

  // Daily count of user-space process crashes.
  scoped_ptr<chromeos_metrics::FrequencyCounter> user_crashes_daily_;

  // Daily count of kernel crashes.
  scoped_ptr<chromeos_metrics::FrequencyCounter> kernel_crashes_daily_;

  // Daily count of unclean shutdowns.
  scoped_ptr<chromeos_metrics::FrequencyCounter> unclean_shutdowns_daily_;

  // Daily count of any crashes (user-space processes, kernel, or
  // unclean shutdowns).
  scoped_ptr<chromeos_metrics::FrequencyCounter> any_crashes_daily_;

  // Sleep period until the next daily usage aggregation performed by
  // the daily use monitor (see ScheduleUseMonitor).
  int usemon_interval_;

  // Scheduled daily use monitor source (see ScheduleUseMonitor).
  GSource* usemon_source_;
};

#endif  // METRICS_DAEMON_H_
