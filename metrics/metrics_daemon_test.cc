// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <utime.h>

#include <string>
#include <vector>

#include <base/at_exit.h>
#include <base/file_util.h>
#include <base/strings/stringprintf.h>
#include <chromeos/dbus/service_constants.h>
#include <gtest/gtest.h>

#include "metrics_daemon.h"
#include "metrics_library_mock.h"
#include "persistent_integer_mock.h"

using base::FilePath;
using base::StringPrintf;
using base::Time;
using base::TimeTicks;
using std::string;
using std::vector;
using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;
using ::testing::AtLeast;
using chromeos_metrics::PersistentIntegerMock;

static const int kSecondsPerDay = 24 * 60 * 60;

static const char kTestDir[] = "test";
static const char kFakeDiskStatsPath[] = "fake-disk-stats";
static const char kFakeDiskStatsFormat[] =
    "    1793     1788    %d   105580    "
    "    196      175     %d    30290    "
    "    0    44060   135850\n";
static string kFakeDiskStats[2];
static const int kFakeReadSectors[] = {80000, 100000};
static const int kFakeWriteSectors[] = {3000, 4000};

static const char kFakeVmStatsPath[] = "fake-vm-stats";
static const char kFakeScalingMaxFreqPath[] = "fake-scaling-max-freq";
static const char kFakeCpuinfoMaxFreqPath[] = "fake-cpuinfo-max-freq";

// This class allows a TimeTicks object to be initialized with seconds
// (rather than microseconds) through the protected TimeTicks(int64)
// constructor.
class TestTicks : public TimeTicks {
 public:
  TestTicks(int64 seconds)
      : TimeTicks(seconds * Time::kMicrosecondsPerSecond) {}
};

class MetricsDaemonTest : public testing::Test {
 protected:
  virtual void SetUp() {
    kFakeDiskStats[0] = base::StringPrintf(kFakeDiskStatsFormat,
                                           kFakeReadSectors[0],
                                           kFakeWriteSectors[0]);
    kFakeDiskStats[1] = base::StringPrintf(kFakeDiskStatsFormat,
                                           kFakeReadSectors[1],
                                           kFakeWriteSectors[1]);
    CreateFakeDiskStatsFile(kFakeDiskStats[0].c_str());
    CreateFakeCpuFrequencyFile(kFakeCpuinfoMaxFreqPath, 10000000);
    CreateFakeCpuFrequencyFile(kFakeScalingMaxFreqPath, 10000000);

    chromeos_metrics::PersistentInteger::SetTestingMode(true);
    daemon_.Init(true, &metrics_lib_, kFakeDiskStatsPath, kFakeVmStatsPath,
        kFakeScalingMaxFreqPath, kFakeCpuinfoMaxFreqPath);

    EXPECT_FALSE(daemon_.user_active_);
    EXPECT_TRUE(daemon_.user_active_last_.is_null());
    EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
    EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);

    base::DeleteFile(FilePath(kTestDir), true);
    base::CreateDirectory(FilePath(kTestDir));

    // Replace original persistent values with mock ones.
    daily_use_mock_ =
        new StrictMock<PersistentIntegerMock>("1.mock");
    daemon_.daily_use_.reset(daily_use_mock_);

    kernel_crash_interval_mock_ =
        new StrictMock<PersistentIntegerMock>("2.mock");
    daemon_.kernel_crash_interval_.reset(kernel_crash_interval_mock_);

    user_crash_interval_mock_ =
        new StrictMock<PersistentIntegerMock>("3.mock");
    daemon_.user_crash_interval_.reset(user_crash_interval_mock_);

    unclean_shutdown_interval_mock_ =
        new StrictMock<PersistentIntegerMock>("4.mock");
    daemon_.unclean_shutdown_interval_.reset(unclean_shutdown_interval_mock_);

  }

  virtual void TearDown() {
    EXPECT_EQ(0, unlink(kFakeDiskStatsPath));
    EXPECT_EQ(0, unlink(kFakeScalingMaxFreqPath));
    EXPECT_EQ(0, unlink(kFakeCpuinfoMaxFreqPath));
  }

  // Adds active use aggregation counters update expectations that the
  // specified count will be added.
  void ExpectActiveUseUpdate(int count) {
    EXPECT_CALL(*daily_use_mock_, Add(count))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*kernel_crash_interval_mock_, Add(count))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*user_crash_interval_mock_, Add(count))
        .Times(1)
        .RetiresOnSaturation();
  }

  // As above, but ignore values of counter updates.
  void IgnoreActiveUseUpdate() {
    EXPECT_CALL(*daily_use_mock_, Add(_))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*kernel_crash_interval_mock_, Add(_))
        .Times(1)
        .RetiresOnSaturation();
    EXPECT_CALL(*user_crash_interval_mock_, Add(_))
        .Times(1)
        .RetiresOnSaturation();
  }

  // Adds a metrics library mock expectation that the specified metric
  // will be generated.
  void ExpectSample(int sample) {
    EXPECT_CALL(metrics_lib_, SendToUMA(_, sample, _, _, _))
        .Times(1)
        .WillOnce(Return(true))
        .RetiresOnSaturation();
  }

  // Adds a metrics library mock expectation that the specified daily
  // use time metric will be generated.
  void ExpectDailyUseTimeSample(int sample) {
    ExpectSample(sample);
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

  // Creates or overwrites an input file containing fake disk stats.
  void CreateFakeDiskStatsFile(const char* fake_stats) {
    if (unlink(kFakeDiskStatsPath) < 0) {
      EXPECT_EQ(errno, ENOENT);
    }
    FILE* f = fopen(kFakeDiskStatsPath, "w");
    EXPECT_EQ(1, fwrite(fake_stats, strlen(fake_stats), 1, f));
    EXPECT_EQ(0, fclose(f));
  }

  // Creates or overwrites an input file containing a fake CPU frequency.
  void CreateFakeCpuFrequencyFile(const char* filename, int frequency) {
    FilePath path(filename);
    base::DeleteFile(path, false);
    std::string frequency_string = StringPrintf("%d\n", frequency);
    int frequency_string_length = frequency_string.length();
    EXPECT_EQ(frequency_string.length(),
        file_util::WriteFile(path, frequency_string.c_str(),
            frequency_string_length));
  }

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;

  // Mocks. They are strict mock so that all unexpected
  // calls are marked as failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;
  StrictMock<PersistentIntegerMock>* daily_use_mock_;
  StrictMock<PersistentIntegerMock>* kernel_crash_interval_mock_;
  StrictMock<PersistentIntegerMock>* user_crash_interval_mock_;
  StrictMock<PersistentIntegerMock>* unclean_shutdown_interval_mock_;
};

TEST_F(MetricsDaemonTest, CheckSystemCrash) {
  static const char kKernelCrashDetected[] = "test-kernel-crash-detected";
  EXPECT_FALSE(daemon_.CheckSystemCrash(kKernelCrashDetected));

  base::FilePath crash_detected(kKernelCrashDetected);
  file_util::WriteFile(crash_detected, "", 0);
  EXPECT_TRUE(base::PathExists(crash_detected));
  EXPECT_TRUE(daemon_.CheckSystemCrash(kKernelCrashDetected));
  EXPECT_FALSE(base::PathExists(crash_detected));
  EXPECT_FALSE(daemon_.CheckSystemCrash(kKernelCrashDetected));
  EXPECT_FALSE(base::PathExists(crash_detected));
  base::DeleteFile(crash_detected, false);
}

TEST_F(MetricsDaemonTest, ReportDailyUse) {
  ExpectDailyUseTimeSample(/* sample */ 2);
  daemon_.ReportDailyUse(/* count */ 90);

  ExpectDailyUseTimeSample(/* sample */ 1);
  daemon_.ReportDailyUse(/* count */ 89);

  // There should be no metrics generated for the calls below.
  daemon_.ReportDailyUse(/* count */ 0);
  daemon_.ReportDailyUse(/* count */ -5);
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
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AtLeast(0));

  DBusMessage* msg = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
  DBusHandlerResult res =
      MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);

  IgnoreActiveUseUpdate();
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
  msg = NewDBusSignalString(power_manager::kPowerManagerServicePath,
                            power_manager::kPowerManagerInterface,
                            power_manager::kPowerStateChangedSignal,
                            signal_args);
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  signal_args.clear();
  IgnoreActiveUseUpdate();
  msg = NewDBusSignalString(login_manager::kSessionManagerServicePath,
                            login_manager::kSessionManagerInterface,
                            login_manager::kScreenIsUnlockedSignal,
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
  msg = NewDBusSignalString(login_manager::kSessionManagerServicePath,
                            login_manager::kSessionManagerInterface,
                            login_manager::kSessionStateChangedSignal,
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
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AtLeast(0));

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(7 * kSecondsPerDay + 15));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 15), daemon_.user_active_last_);

  ExpectActiveUseUpdate(30);
  daemon_.PowerStateChanged("mem", TestTime(7 * kSecondsPerDay + 45));
  EXPECT_EQ(MetricsDaemon::kPowerStateMem, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);

  daemon_.PowerStateChanged("on", TestTime(7 * kSecondsPerDay + 85));
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);

  ExpectActiveUseUpdate(0);
  daemon_.PowerStateChanged("otherstate", TestTime(7 * kSecondsPerDay + 185));
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 185), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SendSample) {
  ExpectSample(3);
  daemon_.SendSample("Dummy.Metric", /* sample */ 3,
                     /* min */ 1, /* max */ 100, /* buckets */ 50);
}

TEST_F(MetricsDaemonTest, SessionStateChanged) {
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AtLeast(0));

  ExpectActiveUseUpdate(0);
  daemon_.SessionStateChanged("started", TestTime(15 * kSecondsPerDay + 20));
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 20), daemon_.user_active_last_);

  ExpectActiveUseUpdate(130);
  daemon_.SessionStateChanged("stopped", TestTime(15 * kSecondsPerDay + 150));
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 150), daemon_.user_active_last_);

  ExpectActiveUseUpdate(0);
  daemon_.SessionStateChanged("otherstate",
                              TestTime(15 * kSecondsPerDay + 300));
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 300), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SetUserActiveState) {
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AtLeast(0));

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(5 * kSecondsPerDay + 10));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(5 * kSecondsPerDay + 10), daemon_.user_active_last_);

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 20));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 20), daemon_.user_active_last_);

  ExpectActiveUseUpdate(100);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 120));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 120), daemon_.user_active_last_);

  ExpectActiveUseUpdate(110);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 230));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 230), daemon_.user_active_last_);

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 260));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 260), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SetUserActiveStateTimeJump) {
  // Ignore calls to SendToUMA.
  EXPECT_CALL(metrics_lib_, SendToUMA(_, _, _, _, _)).Times(AtLeast(0));

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 500));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 500), daemon_.user_active_last_);

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 300));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 300), daemon_.user_active_last_);

  ExpectActiveUseUpdate(0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 1000));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 1000), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, ReportDiskStats) {
  long int read_sectors_now, write_sectors_now;

  CreateFakeDiskStatsFile(kFakeDiskStats[1].c_str());
  daemon_.DiskStatsReadStats(&read_sectors_now, &write_sectors_now);
  EXPECT_EQ(read_sectors_now, kFakeReadSectors[1]);
  EXPECT_EQ(write_sectors_now, kFakeWriteSectors[1]);

  MetricsDaemon::StatsState s_state = daemon_.stats_state_;
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (kFakeReadSectors[1] - kFakeReadSectors[0]) / 30,
                        _, _, _));
  EXPECT_CALL(metrics_lib_,
              SendToUMA(_, (kFakeWriteSectors[1] - kFakeWriteSectors[0]) / 30,
                        _, _, _));
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, _, _));  // SendCpuThrottleMetrics
  daemon_.StatsCallback();
  EXPECT_TRUE(s_state != daemon_.stats_state_);
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
  // Not enough fields.
  EXPECT_FALSE(daemon_.ProcessMeminfo(meminfo));
}

TEST_F(MetricsDaemonTest, ParseVmStats) {
  static char kVmStats[] = "pswpin 1345\npswpout 8896\n"
    "foo 100\nbar 200\npgmajfault 42\netcetc 300\n";
  struct MetricsDaemon::VmstatRecord stats;
  EXPECT_TRUE(daemon_.VmStatsParseStats(kVmStats, &stats));
  EXPECT_EQ(stats.page_faults_, 42);
  EXPECT_EQ(stats.swap_in_, 1345);
  EXPECT_EQ(stats.swap_out_, 8896);
}

TEST_F(MetricsDaemonTest, ReadFreqToInt) {
  const int fake_scaled_freq = 1666999;
  const int fake_max_freq = 2000000;
  int scaled_freq = 0;
  int max_freq = 0;
  CreateFakeCpuFrequencyFile(kFakeScalingMaxFreqPath, fake_scaled_freq);
  CreateFakeCpuFrequencyFile(kFakeCpuinfoMaxFreqPath, fake_max_freq);
  EXPECT_TRUE(daemon_.testing_);
  EXPECT_TRUE(daemon_.ReadFreqToInt(kFakeScalingMaxFreqPath, &scaled_freq));
  EXPECT_TRUE(daemon_.ReadFreqToInt(kFakeCpuinfoMaxFreqPath, &max_freq));
  EXPECT_EQ(fake_scaled_freq, scaled_freq);
  EXPECT_EQ(fake_max_freq, max_freq);
}

TEST_F(MetricsDaemonTest, SendCpuThrottleMetrics) {
  CreateFakeCpuFrequencyFile(kFakeCpuinfoMaxFreqPath, 2001000);
  // Test the 101% and 100% cases.
  CreateFakeCpuFrequencyFile(kFakeScalingMaxFreqPath, 2001000);
  EXPECT_TRUE(daemon_.testing_);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, 101, 101));
  daemon_.SendCpuThrottleMetrics();
  CreateFakeCpuFrequencyFile(kFakeScalingMaxFreqPath, 2000000);
  EXPECT_CALL(metrics_lib_, SendEnumToUMA(_, 100, 101));
  daemon_.SendCpuThrottleMetrics();
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  // Some libchrome calls need this.
  base::AtExitManager at_exit_manager;

  return RUN_ALL_TESTS();
}
