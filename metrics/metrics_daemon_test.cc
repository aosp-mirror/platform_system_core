// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utime.h>

#include <string>
#include <vector>

#include <base/file_util.h>
#include <base/stringprintf.h>
#include <gtest/gtest.h>

#include "counter_mock.h"
#include "metrics_daemon.h"
#include "metrics_library_mock.h"

using base::Time;
using base::TimeTicks;
using chromeos_metrics::FrequencyCounter;
using chromeos_metrics::FrequencyCounterMock;
using chromeos_metrics::TaggedCounterMock;
using chromeos_metrics::TaggedCounterReporter;
using chromeos_metrics::TaggedCounterReporterMock;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::AtLeast;

static const int kSecondsPerDay = 24 * 60 * 60;

static const char kTestDir[] = "test";
static const char kLastFile[] = "test/last";
static const char kCurrentFile[] = "test/current";
static const char kFakeDiskStatsPath[] = "fake-disk-stats";
static const char kFakeDiskStatsFormat[] =
    "    1793     1788    %d   105580    "
    "    196      175     %d    30290    "
    "    0    44060   135850\n";
static string kFakeDiskStats[2];
static const int kFakeReadSectors[] = {80000, 100000};
static const int kFakeWriteSectors[] = {3000, 4000};

// This class allows a TimeTicks object to be initialized with seconds
// (rather than microseconds) through the protected TimeTicks(int64)
// constructor.
class TestTicks : public TimeTicks {
 public:
  TestTicks(int64 seconds)
      : TimeTicks(seconds * Time::kMicrosecondsPerSecond) {}
};

// Overloaded for test failure printing purposes.
static std::ostream& operator<<(std::ostream& o, const Time& time) {
  o << time.ToInternalValue() << "us";
  return o;
};

class MetricsDaemonTest : public testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_EQ(NULL, daemon_.daily_use_.get());
    EXPECT_EQ(NULL, daemon_.kernel_crash_interval_.get());
    EXPECT_EQ(NULL, daemon_.user_crash_interval_.get());
    kFakeDiskStats[0] = StringPrintf(kFakeDiskStatsFormat,
                                     kFakeReadSectors[0], kFakeWriteSectors[0]);
    kFakeDiskStats[1] = StringPrintf(kFakeDiskStatsFormat,
                                     kFakeReadSectors[1], kFakeWriteSectors[1]);
    CreateFakeDiskStatsFile(kFakeDiskStats[0].c_str());
    daemon_.Init(true, &metrics_lib_, kFakeDiskStatsPath);

    // Check configuration of a few histograms.
    FrequencyCounter* frequency_counter =
        daemon_.frequency_counters_[MetricsDaemon::kMetricAnyCrashesDailyName];
    const TaggedCounterReporter* reporter = GetReporter(frequency_counter);
    EXPECT_EQ(MetricsDaemon::kMetricAnyCrashesDailyName,
              reporter->histogram_name());
    EXPECT_EQ(chromeos_metrics::kSecondsPerDay,
              frequency_counter->cycle_duration());
    EXPECT_EQ(MetricsDaemon::kMetricCrashFrequencyMin, reporter->min());
    EXPECT_EQ(MetricsDaemon::kMetricCrashFrequencyMax, reporter->max());
    EXPECT_EQ(MetricsDaemon::kMetricCrashFrequencyBuckets, reporter->buckets());

    frequency_counter =
        daemon_.frequency_counters_[MetricsDaemon::kMetricAnyCrashesWeeklyName];
    reporter = GetReporter(frequency_counter);
    EXPECT_EQ(MetricsDaemon::kMetricAnyCrashesWeeklyName,
              reporter->histogram_name());
    EXPECT_EQ(chromeos_metrics::kSecondsPerWeek,
              frequency_counter->cycle_duration());

    EXPECT_EQ(MetricsDaemon::kMetricKernelCrashIntervalName,
              daemon_.kernel_crash_interval_->histogram_name());
    EXPECT_EQ(MetricsDaemon::kMetricCrashIntervalMin,
              daemon_.kernel_crash_interval_->min());
    EXPECT_EQ(MetricsDaemon::kMetricCrashIntervalMax,
              daemon_.kernel_crash_interval_->max());
    EXPECT_EQ(MetricsDaemon::kMetricCrashIntervalBuckets,
              daemon_.kernel_crash_interval_->buckets());

    EXPECT_EQ(MetricsDaemon::kMetricUncleanShutdownIntervalName,
              daemon_.unclean_shutdown_interval_->histogram_name());

    // Tests constructor initialization. Switches to mock counters.
    EXPECT_TRUE(NULL != daemon_.daily_use_.get());
    EXPECT_TRUE(NULL != daemon_.kernel_crash_interval_.get());
    EXPECT_TRUE(NULL != daemon_.user_crash_interval_.get());

    // Allocates mock counter and transfers ownership.
    daily_use_ = new StrictMock<TaggedCounterMock>();
    daemon_.daily_use_.reset(daily_use_);
    kernel_crash_interval_ = new StrictMock<TaggedCounterReporterMock>();
    daemon_.kernel_crash_interval_.reset(kernel_crash_interval_);
    user_crash_interval_ = new StrictMock<TaggedCounterReporterMock>();
    daemon_.user_crash_interval_.reset(user_crash_interval_);
    unclean_shutdown_interval_ = new StrictMock<TaggedCounterReporterMock>();
    daemon_.unclean_shutdown_interval_.reset(unclean_shutdown_interval_);

    // Reset all frequency counter reporters to mocks for further testing.
    MetricsDaemon::FrequencyCounters::iterator i;
    for (i = daemon_.frequency_counters_.begin();
         i != daemon_.frequency_counters_.end(); ++i) {
      delete i->second;
      i->second = new StrictMock<FrequencyCounterMock>();
    }

    EXPECT_FALSE(daemon_.user_active_);
    EXPECT_TRUE(daemon_.user_active_last_.is_null());
    EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
    EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);

    file_util::Delete(FilePath(kTestDir), true);
    file_util::CreateDirectory(FilePath(kTestDir));
  }

  virtual void TearDown() {
    EXPECT_EQ(unlink(kFakeDiskStatsPath), 0);
  }

  const TaggedCounterReporter*
  GetReporter(FrequencyCounter* frequency_counter) const {
    return static_cast<const TaggedCounterReporter*>(
        &frequency_counter->tagged_counter());
  }

  void ExpectFrequencyFlushCalls() {
    MetricsDaemon::FrequencyCounters::iterator i;
    for (i = daemon_.frequency_counters_.begin();
         i != daemon_.frequency_counters_.end(); ++i) {
      FrequencyCounterMock* mock =
          static_cast<FrequencyCounterMock*>(i->second);
      EXPECT_CALL(*mock, FlushFinishedCycles());
    }
  }

  // Adds active use aggregation counters update expectations that the
  // specified tag/count update will be generated.
  void ExpectActiveUseUpdate(int daily_tag, int count) {
    EXPECT_CALL(*daily_use_, Update(daily_tag, count))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*kernel_crash_interval_, Update(0, count))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*user_crash_interval_, Update(0, count))
        .Times(1)
        .RetiresOnSaturation();
    ExpectFrequencyFlushCalls();
  }

  // Adds active use aggregation counters update expectations that
  // ignore the update arguments.
  void IgnoreActiveUseUpdate() {
    EXPECT_CALL(*daily_use_, Update(_, _))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*kernel_crash_interval_, Update(_, _))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*user_crash_interval_, Update(_, _))
        .Times(1)
        .RetiresOnSaturation();
    ExpectFrequencyFlushCalls();
  }

  // Adds a metrics library mock expectation that the specified metric
  // will be generated.
  void ExpectMetric(const string& name, int sample,
                    int min, int max, int buckets) {
    EXPECT_CALL(metrics_lib_, SendToUMA(name, sample, min, max, buckets))
        .Times(1)
        .WillOnce(Return(true))
        .RetiresOnSaturation();
  }

  // Adds a metrics library mock expectation that the specified daily
  // use time metric will be generated.
  void ExpectDailyUseTimeMetric(int sample) {
    ExpectMetric(MetricsDaemon::kMetricDailyUseTimeName, sample,
                 MetricsDaemon::kMetricDailyUseTimeMin,
                 MetricsDaemon::kMetricDailyUseTimeMax,
                 MetricsDaemon::kMetricDailyUseTimeBuckets);
  }

  // Converts from seconds to a Time object.
  Time TestTime(int64 seconds) {
    return Time::FromInternalValue(seconds * Time::kMicrosecondsPerSecond);
  }

  // Creates a new DBus signal message with zero or more string arguments.
  // The message can be deallocated through DeleteDBusMessage.
  //
  // |path| is the object emitting the signal.
  // |interface| is the interface the signal is emitted from.
  // |name| is the name of the signal.
  // |arg_values| contains the values of the string arguments.
  DBusMessage* NewDBusSignalString(const string& path,
                                   const string& interface,
                                   const string& name,
                                   const vector<string>& arg_values) {
    DBusMessage* msg = dbus_message_new_signal(path.c_str(),
                                               interface.c_str(),
                                               name.c_str());
    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);
    for (vector<string>::const_iterator it = arg_values.begin();
         it != arg_values.end(); ++it) {
      const char* str_value = it->c_str();
      dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &str_value);
    }
    return msg;
  }

  // Deallocates the DBus message |msg| previously allocated through
  // dbus_message_new*.
  void DeleteDBusMessage(DBusMessage* msg) {
    dbus_message_unref(msg);
  }

  // Gets the frequency counter for the given name.
  FrequencyCounterMock& GetFrequencyMock(const char* histogram_name) {
    return *static_cast<FrequencyCounterMock*>(
        daemon_.frequency_counters_[histogram_name]);
  }

  // Creates or overwrites an input file containing fake disk stats.
  void CreateFakeDiskStatsFile(const char* fake_stats) {
    if (unlink(kFakeDiskStatsPath) < 0) {
      EXPECT_EQ(errno, ENOENT);
    }
    FILE* f = fopen(kFakeDiskStatsPath, "w");
    EXPECT_EQ(1, fwrite(fake_stats, strlen(fake_stats), 1, f));
    EXPECT_EQ(0, fclose(f));
  }

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;

  // Metrics library mock. It's a strict mock so that all unexpected
  // metric generation calls are marked as failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;

  // Counter mocks. They are strict mocks so that all unexpected
  // update calls are marked as failures. They are pointers so that
  // they can replace the scoped_ptr's allocated by the daemon.
  StrictMock<TaggedCounterMock>* daily_use_;
  StrictMock<TaggedCounterReporterMock>* kernel_crash_interval_;
  StrictMock<TaggedCounterReporterMock>* user_crash_interval_;
  StrictMock<TaggedCounterReporterMock>* unclean_shutdown_interval_;
};

TEST_F(MetricsDaemonTest, CheckSystemCrash) {
  static const char kKernelCrashDetected[] = "test-kernel-crash-detected";
  EXPECT_FALSE(daemon_.CheckSystemCrash(kKernelCrashDetected));

  FilePath crash_detected(kKernelCrashDetected);
  file_util::WriteFile(crash_detected, "", 0);
  EXPECT_TRUE(file_util::PathExists(crash_detected));
  EXPECT_TRUE(daemon_.CheckSystemCrash(kKernelCrashDetected));
  EXPECT_FALSE(file_util::PathExists(crash_detected));
  EXPECT_FALSE(daemon_.CheckSystemCrash(kKernelCrashDetected));
  EXPECT_FALSE(file_util::PathExists(crash_detected));
  file_util::Delete(crash_detected, false);
}

TEST_F(MetricsDaemonTest, ReportDailyUse) {
  ExpectDailyUseTimeMetric(/* sample */ 2);
  MetricsDaemon::ReportDailyUse(&daemon_, /* tag */ 20, /* count */ 90);

  ExpectDailyUseTimeMetric(/* sample */ 1);
  MetricsDaemon::ReportDailyUse(&daemon_, /* tag */ 23, /* count */ 89);

  // There should be no metrics generated for the calls below.
  MetricsDaemon::ReportDailyUse(&daemon_, /* tag */ 50, /* count */ 0);
  MetricsDaemon::ReportDailyUse(&daemon_, /* tag */ 60, /* count */ -5);
}

TEST_F(MetricsDaemonTest, LookupPowerState) {
  EXPECT_EQ(MetricsDaemon::kPowerStateOn,
            daemon_.LookupPowerState("on"));
  EXPECT_EQ(MetricsDaemon::kPowerStateMem,
            daemon_.LookupPowerState("mem"));
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState,
            daemon_.LookupPowerState("somestate"));
}

TEST_F(MetricsDaemonTest, LookupSessionState) {
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted,
            daemon_.LookupSessionState("started"));
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped,
            daemon_.LookupSessionState("stopped"));
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState,
            daemon_.LookupSessionState("somestate"));
}

TEST_F(MetricsDaemonTest, MessageFilter) {
  DBusMessage* msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
  DBusHandlerResult res =
      MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);

  IgnoreActiveUseUpdate();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesDailyName),
      Update(1))
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesWeeklyName),
      Update(1))
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricUserCrashesDailyName),
      Update(1))
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricUserCrashesWeeklyName),
      Update(1))
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(*user_crash_interval_, Flush())
      .Times(1)
      .RetiresOnSaturation();
  vector<string> signal_args;
  msg = NewDBusSignalString("/",
                            "org.chromium.CrashReporter",
                            "UserCrash",
                            signal_args);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  signal_args.clear();
  signal_args.push_back("on");
  msg = NewDBusSignalString("/",
                            "org.chromium.PowerManager",
                            "PowerStateChanged",
                            signal_args);
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  signal_args.clear();
  IgnoreActiveUseUpdate();
  msg = NewDBusSignalString("/",
                            "org.chromium.PowerManager",
                            "ScreenIsUnlocked",
                            signal_args);
  EXPECT_FALSE(daemon_.user_active_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  IgnoreActiveUseUpdate();
  signal_args.clear();
  signal_args.push_back("started");
  signal_args.push_back("bob");  // arbitrary username
  msg = NewDBusSignalString("/org/chromium/SessionManager",
                            "org.chromium.SessionManagerInterface",
                            "SessionStateChanged",
                            signal_args);
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  signal_args.clear();
  signal_args.push_back("randomstate");
  signal_args.push_back("bob");  // arbitrary username
  msg = NewDBusSignalString("/",
                            "org.chromium.UnknownService.Manager",
                            "StateChanged",
                            signal_args);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);
}

TEST_F(MetricsDaemonTest, PowerStateChanged) {
  ExpectActiveUseUpdate(7, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(7 * kSecondsPerDay + 15));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 15), daemon_.user_active_last_);

  ExpectActiveUseUpdate(7, 30);
  daemon_.PowerStateChanged("mem", TestTime(7 * kSecondsPerDay + 45));
  EXPECT_EQ(MetricsDaemon::kPowerStateMem, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);

  daemon_.PowerStateChanged("on", TestTime(7 * kSecondsPerDay + 85));
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);

  ExpectActiveUseUpdate(7, 0);
  daemon_.PowerStateChanged("otherstate", TestTime(7 * kSecondsPerDay + 185));
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 185), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, ProcessKernelCrash) {
  IgnoreActiveUseUpdate();
  EXPECT_CALL(*kernel_crash_interval_, Flush())
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesDailyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesWeeklyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricKernelCrashesDailyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricKernelCrashesWeeklyName),
              Update(1));
  daemon_.ProcessKernelCrash();
}

TEST_F(MetricsDaemonTest, ProcessUncleanShutdown) {
  IgnoreActiveUseUpdate();
  EXPECT_CALL(*unclean_shutdown_interval_, Flush())
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesDailyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesWeeklyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricUncleanShutdownsDailyName),
              Update(1));
  EXPECT_CALL(
      GetFrequencyMock(MetricsDaemon::kMetricUncleanShutdownsWeeklyName),
      Update(1));
  daemon_.ProcessUncleanShutdown();
}

TEST_F(MetricsDaemonTest, ProcessUserCrash) {
  IgnoreActiveUseUpdate();
  EXPECT_CALL(*user_crash_interval_, Flush())
      .Times(1)
      .RetiresOnSaturation();
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesDailyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricAnyCrashesWeeklyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricUserCrashesDailyName),
              Update(1));
  EXPECT_CALL(GetFrequencyMock(MetricsDaemon::kMetricUserCrashesWeeklyName),
              Update(1));
  daemon_.ProcessUserCrash();
}

TEST_F(MetricsDaemonTest, SendMetric) {
  ExpectMetric("Dummy.Metric", 3, 1, 100, 50);
  daemon_.SendMetric("Dummy.Metric", /* sample */ 3,
                     /* min */ 1, /* max */ 100, /* buckets */ 50);
}

TEST_F(MetricsDaemonTest, SessionStateChanged) {
  ExpectActiveUseUpdate(15, 0);
  daemon_.SessionStateChanged("started", TestTime(15 * kSecondsPerDay + 20));
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 20), daemon_.user_active_last_);

  ExpectActiveUseUpdate(15, 130);
  daemon_.SessionStateChanged("stopped", TestTime(15 * kSecondsPerDay + 150));
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 150), daemon_.user_active_last_);

  ExpectActiveUseUpdate(15, 0);
  daemon_.SessionStateChanged("otherstate",
                              TestTime(15 * kSecondsPerDay + 300));
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 300), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SetUserActiveState) {
  ExpectActiveUseUpdate(5, 0);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(5 * kSecondsPerDay + 10));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(5 * kSecondsPerDay + 10), daemon_.user_active_last_);

  ExpectActiveUseUpdate(6, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 20));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 20), daemon_.user_active_last_);

  ExpectActiveUseUpdate(6, 100);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 120));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 120), daemon_.user_active_last_);

  ExpectActiveUseUpdate(6, 110);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 230));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 230), daemon_.user_active_last_);

  ExpectActiveUseUpdate(6, 0);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 260));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 260), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SetUserActiveStateTimeJump) {
  ExpectActiveUseUpdate(10, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 500));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 500), daemon_.user_active_last_);

  ExpectActiveUseUpdate(10, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 300));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 300), daemon_.user_active_last_);

  ExpectActiveUseUpdate(10, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 1000));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 1000), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, GetHistogramPath) {
  EXPECT_EQ("/var/log/metrics/Logging.AnyCrashesDaily",
            daemon_.GetHistogramPath(
                MetricsDaemon::kMetricAnyCrashesDailyName).value());
}

TEST_F(MetricsDaemonTest, ReportDiskStats) {
  long int read_sectors_now, write_sectors_now;

  CreateFakeDiskStatsFile(kFakeDiskStats[1].c_str());
  daemon_.DiskStatsReadStats(&read_sectors_now, &write_sectors_now);
  EXPECT_EQ(read_sectors_now, kFakeReadSectors[1]);
  EXPECT_EQ(write_sectors_now, kFakeWriteSectors[1]);

  MetricsDaemon::DiskStatsState ds_state = daemon_.diskstats_state_;
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (kFakeReadSectors[1] - kFakeReadSectors[0]) / 30,
                        _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (kFakeWriteSectors[1] - kFakeWriteSectors[0]) / 30,
                        _, _, _));
  daemon_.DiskStatsCallback();
  EXPECT_TRUE(ds_state != daemon_.diskstats_state_);
}

TEST_F(MetricsDaemonTest, ProcessMeminfo) {
  string meminfo = "\
MemTotal:        2000000 kB\n\
MemFree:          500000 kB\n\
Buffers:         1000000 kB\n\
Cached:           213652 kB\n\
SwapCached:            0 kB\n\
Active:           133400 kB\n\
Inactive:         183396 kB\n\
Active(anon):      92984 kB\n\
Inactive(anon):    58860 kB\n\
Active(file):      40416 kB\n\
Inactive(file):   124536 kB\n\
Unevictable:           0 kB\n\
Mlocked:               0 kB\n\
SwapTotal:             0 kB\n\
SwapFree:              0 kB\n\
Dirty:                40 kB\n\
Writeback:             0 kB\n\
AnonPages:         92652 kB\n\
Mapped:            59716 kB\n\
Shmem:             59196 kB\n\
Slab:              16656 kB\n\
SReclaimable:       6132 kB\n\
SUnreclaim:        10524 kB\n\
KernelStack:        1648 kB\n\
PageTables:         2780 kB\n\
NFS_Unstable:          0 kB\n\
Bounce:                0 kB\n\
WritebackTmp:          0 kB\n\
CommitLimit:      970656 kB\n\
Committed_AS:    1260528 kB\n\
VmallocTotal:     122880 kB\n\
VmallocUsed:       12144 kB\n\
VmallocChunk:     103824 kB\n\
DirectMap4k:        9636 kB\n\
DirectMap2M:     1955840 kB\n\
";
  // All enum calls must report percents.
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, _, 100))
      .Times(AtLeast(1));
  // Check that MemFree is correctly computed at 25%.
  EXPECT_CALL(metrics_lib_, SendEnumToUMA("Platform.MeminfoMemFree", 25, 100))
      .Times(AtLeast(1));
  // Check that we call SendToUma at least once (log histogram).
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _))
      .Times(AtLeast(1));
  // Make sure we don't report fields not in the list.
  EXPECT_CALL(metrics_lib_, SendToUMA("Platform.MeminfoMlocked", _, _, _, _))
      .Times(0);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA("Platform.MeminfoMlocked", _, _))
      .Times(0);
  EXPECT_TRUE(daemon_.ProcessMeminfo(meminfo));
}

TEST_F(MetricsDaemonTest, ProcessMeminfo2) {
  string meminfo = "\
MemTotal:        2000000 kB\n\
MemFree:         1000000 kB\n\
";
  /* Not enough fields */
  EXPECT_FALSE(daemon_.ProcessMeminfo(meminfo));
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
