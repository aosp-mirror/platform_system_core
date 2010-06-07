// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_daemon.h"
#include "metrics_library_mock.h"

#include <sys/file.h>

#include <base/eintr_wrapper.h>
#include <base/file_util.h>
#include <base/logging.h>
#include <base/string_util.h>
#include <gtest/gtest.h>

using base::Time;
using base::TimeTicks;
using ::testing::Mock;
using ::testing::Return;
using ::testing::StrictMock;

static const char kTestDailyUseRecordFile[] = "daily-usage-test";
static const char kDoesNotExistFile[] = "/does/not/exist";

static const int kSecondsPerDay = 24 * 60 * 60;

// This class allows a TimeTicks object to be initialized with seconds
// (rather than microseconds) through the protected TimeTicks(int64)
// constructor.
class TestTicks : public TimeTicks {
 public:
  TestTicks(int64 seconds)
      : TimeTicks(seconds * Time::kMicrosecondsPerSecond) {}
};

// Overloaded for test failure printing purposes.
static std::ostream& operator<<(std::ostream& o, const TimeTicks& ticks) {
  o << ticks.ToInternalValue() << "us";
  return o;
};

// Overloaded for test failure printing purposes.
static std::ostream& operator<<(std::ostream& o, const Time& time) {
  o << time.ToInternalValue() << "us";
  return o;
};

class MetricsDaemonTest : public testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_EQ(NULL, daemon_.daily_use_record_file_);
    daemon_.Init(true, &metrics_lib_);

    // Tests constructor initialization. Switches to a test daily use
    // record file.
    EXPECT_TRUE(NULL != daemon_.daily_use_record_file_);
    daemon_.daily_use_record_file_ = kTestDailyUseRecordFile;
    EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());
    EXPECT_EQ(0, daemon_.daily_use_day_last_);
    EXPECT_FALSE(daemon_.user_active_);
    EXPECT_TRUE(daemon_.user_active_last_.is_null());
    EXPECT_EQ(MetricsDaemon::kUnknownNetworkState, daemon_.network_state_);
    EXPECT_TRUE(daemon_.network_state_last_.is_null());
    EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
    EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);

    // The test fixture object will be used by the log message handler.
    daemon_test_ = this;
    logging::SetLogMessageHandler(HandleLogMessages);
  }

  virtual void TearDown() {
    logging::SetLogMessageHandler(NULL);
    daemon_test_ = NULL;
    file_util::Delete(FilePath(kTestDailyUseRecordFile), false);
  }

  // Collects log messages in the |daemon_log_| member string so that
  // they can be analyzed for errors and expected behavior.
  static bool HandleLogMessages(int severity, const std::string& str) {
    daemon_test_->daemon_log_.append(str);
    daemon_test_->daemon_log_.append("\n");

    // Returning true would mute the log.
    return false;
  }

  // Returns true if the daemon log contains |pattern|, false otherwise.
  bool LogContains(const std::string& pattern) {
    return daemon_log_.find(pattern) != std::string::npos;
  }

  // Adds a metrics library mock expectation that the specified metric
  // will be generated.
  void ExpectMetric(const std::string& name, int sample,
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

  // Adds a metrics library mock expectation that the specified time
  // to network dropping metric will be generated.
  void ExpectTimeToNetworkDropMetric(int sample) {
    ExpectMetric(MetricsDaemon::kMetricTimeToNetworkDropName, sample,
                 MetricsDaemon::kMetricTimeToNetworkDropMin,
                 MetricsDaemon::kMetricTimeToNetworkDropMax,
                 MetricsDaemon::kMetricTimeToNetworkDropBuckets);
  }

  Time TestTime(int64 seconds) {
    return Time::FromInternalValue(seconds * Time::kMicrosecondsPerSecond);
  }

  // Asserts that the daily use record file contains the specified
  // contents.
  testing::AssertionResult AssertDailyUseRecord(const char* expr_day,
                                                const char* expr_seconds,
                                                int expected_day,
                                                int expected_seconds) {
    int fd = HANDLE_EINTR(open(daemon_.daily_use_record_file_, O_RDONLY));
    if (fd < 0) {
      testing::Message msg;
      msg << "Unable to open " << daemon_.daily_use_record_file_;
      return testing::AssertionFailure(msg);
    }

    MetricsDaemon::UseRecord record;
    if (!file_util::ReadFromFD(fd, reinterpret_cast<char*>(&record),
                               sizeof(record))) {
      testing::Message msg;
      msg << "Unable to read " << sizeof(record) << " bytes from "
          << daemon_.daily_use_record_file_;
      HANDLE_EINTR(close(fd));
      return testing::AssertionFailure(msg);
    }

    if (record.day_ != expected_day || record.seconds_ != expected_seconds) {
      testing::Message msg;
      msg << "actual use record (" << record.day_ << ", " << record.seconds_
          << ") expected (" << expected_day << ", " << expected_seconds << ")";
      HANDLE_EINTR(close(fd));
      return testing::AssertionFailure(msg);
    }

    HANDLE_EINTR(close(fd));
    return testing::AssertionSuccess();
  }

  // Returns true if the daily use record file does not exist or is
  // empty, false otherwise.
  bool AssertNoOrEmptyUseRecordFile() {
    FilePath record_file(daemon_.daily_use_record_file_);
    int64 record_file_size;
    return !file_util::PathExists(record_file) ||
        (file_util::GetFileSize(record_file, &record_file_size) &&
         record_file_size == 0);
  }

  // Creates a new DBus signal message with a single string
  // argument. The message can be deallocated through
  // DeleteDBusMessage.
  //
  // |path| is the object emitting the signal.
  // |interface| is the interface the signal is emitted from.
  // |name| is the name of the signal.
  // |arg_value| is the value of the string argument.
  DBusMessage* NewDBusSignalString(const std::string& path,
                                   const std::string& interface,
                                   const std::string& name,
                                   const std::string& arg_value) {
    DBusMessage* msg = dbus_message_new_signal(path.c_str(),
                                               interface.c_str(),
                                               name.c_str());
    DBusMessageIter iter;
    dbus_message_iter_init_append(msg, &iter);
    const char* arg_value_c = arg_value.c_str();
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &arg_value_c);
    return msg;
  }

  // Deallocates the DBus message |msg| previously allocated through
  // dbus_message_new*.
  void DeleteDBusMessage(DBusMessage* msg) {
    dbus_message_unref(msg);
  }

  // Pointer to the current test fixture.
  static MetricsDaemonTest* daemon_test_;

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;

  // Metrics library mock. It's a strict mock so that all unexpected
  // metric generation calls are marked as failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;

  // The accumulated metrics daemon log.
  std::string daemon_log_;
};

// static
MetricsDaemonTest* MetricsDaemonTest::daemon_test_ = NULL;

TEST_F(MetricsDaemonTest, LogDailyUseRecordBadFileLocation) {
  // Checks that the daemon doesn't die badly if the file can't be
  // created.
  daemon_.daily_use_record_file_ = kDoesNotExistFile;
  daemon_.LogDailyUseRecord(10, 20);
  EXPECT_TRUE(LogContains("Unable to open the daily use file: "
                          "No such file or directory"));
  EXPECT_EQ(0, daemon_.daily_use_day_last_);
  file_util::Delete(FilePath(kDoesNotExistFile), false);
}

TEST_F(MetricsDaemonTest, LogDailyUseRecordOnLogin) {
  daemon_.LogDailyUseRecord(/* day */ 5, /* seconds */ 120);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 120);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);

  daemon_.LogDailyUseRecord(/* day */ 5, /* seconds */ 0);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 120);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);

  daemon_.LogDailyUseRecord(/* day */ 5, /* seconds */ 240);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 360);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);

  ExpectDailyUseTimeMetric(/* sample */ 6);
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 0);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
}

TEST_F(MetricsDaemonTest, LogDailyUseRecordRoundDown) {
  daemon_.LogDailyUseRecord(/* day */ 7, /* seconds */ 89);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 89);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);

  ExpectDailyUseTimeMetric(/* sample */ 1);
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 15);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 15);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
}

TEST_F(MetricsDaemonTest, LogDailyUseRecordRoundUp) {
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 0);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);

  // Tests rounding use time to the closest minute.
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 90);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 90);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);

  ExpectDailyUseTimeMetric(/* sample */ 2);
  daemon_.LogDailyUseRecord(/* day */ 7, /* seconds */ 89);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 89);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);
}

TEST_F(MetricsDaemonTest, LookupNetworkState) {
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline,
            daemon_.LookupNetworkState("online"));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline,
            daemon_.LookupNetworkState("offline"));
  EXPECT_EQ(MetricsDaemon::kUnknownNetworkState,
            daemon_.LookupNetworkState("somestate"));
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

  msg = NewDBusSignalString("/",
                            "org.chromium.flimflam.Manager",
                            "StateChanged",
                            "online");
  EXPECT_EQ(MetricsDaemon::kUnknownNetworkState, daemon_.network_state_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  msg = NewDBusSignalString("/",
                            "org.chromium.PowerManager",
                            "PowerStateChanged",
                            "on");
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  msg = NewDBusSignalString("/",
                            "org.chromium.PowerManager",
                            "ScreenIsUnlocked",
                            "");
  EXPECT_FALSE(daemon_.user_active_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  msg = NewDBusSignalString("/org/chromium/SessionManager",
                            "org.chromium.SessionManagerInterface",
                            "SessionStateChanged",
                            "started");
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  msg = NewDBusSignalString("/",
                            "org.chromium.UnknownService.Manager",
                            "StateChanged",
                            "randomstate");
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_NOT_YET_HANDLED, res);
  DeleteDBusMessage(msg);
}

TEST_F(MetricsDaemonTest, NetStateChangedSimpleDrop) {
  daemon_.NetStateChanged("online", TestTicks(10));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(10), daemon_.network_state_last_);

  ExpectTimeToNetworkDropMetric(20);
  daemon_.NetStateChanged("offline", TestTicks(30));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(30), daemon_.network_state_last_);
}

TEST_F(MetricsDaemonTest, NetStateChangedSuspend) {
  daemon_.NetStateChanged("offline", TestTicks(30));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(30), daemon_.network_state_last_);

  daemon_.NetStateChanged("online", TestTicks(60));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(60), daemon_.network_state_last_);

  daemon_.power_state_ = MetricsDaemon::kPowerStateMem;
  daemon_.NetStateChanged("offline", TestTicks(85));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(85), daemon_.network_state_last_);

  daemon_.NetStateChanged("somestate", TestTicks(90));
  EXPECT_EQ(MetricsDaemon::kUnknownNetworkState, daemon_.network_state_);
  EXPECT_EQ(TestTicks(90), daemon_.network_state_last_);

  daemon_.NetStateChanged("offline", TestTicks(95));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(95), daemon_.network_state_last_);

  daemon_.power_state_ = MetricsDaemon::kPowerStateOn;
  daemon_.NetStateChanged("online", TestTicks(105));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(105), daemon_.network_state_last_);

  ExpectTimeToNetworkDropMetric(3);
  daemon_.NetStateChanged("offline", TestTicks(108));
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(TestTicks(108), daemon_.network_state_last_);
}

TEST_F(MetricsDaemonTest, PowerStateChanged) {
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(7 * kSecondsPerDay + 15));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 15), daemon_.user_active_last_);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.PowerStateChanged("mem", TestTime(7 * kSecondsPerDay + 45));
  EXPECT_EQ(MetricsDaemon::kPowerStateMem, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 30);

  daemon_.PowerStateChanged("on", TestTime(7 * kSecondsPerDay + 85));
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 30);

  daemon_.PowerStateChanged("otherstate", TestTime(7 * kSecondsPerDay + 185));
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 185), daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 30);
}

TEST_F(MetricsDaemonTest, SendMetric) {
  ExpectMetric("Dummy.Metric", 3, 1, 100, 50);
  daemon_.SendMetric("Dummy.Metric", /* sample */ 3,
                     /* min */ 1, /* max */ 100, /* buckets */ 50);
}

TEST_F(MetricsDaemonTest, SessionStateChanged) {
  daemon_.SessionStateChanged("started", TestTime(15 * kSecondsPerDay + 20));
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 20), daemon_.user_active_last_);
  EXPECT_EQ(15, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.SessionStateChanged("stopped", TestTime(15 * kSecondsPerDay + 150));
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 150), daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 15, /* seconds */ 130);

  daemon_.SessionStateChanged("otherstate",
                              TestTime(15 * kSecondsPerDay + 300));
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 300), daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 15, /* seconds */ 130);
}

TEST_F(MetricsDaemonTest, SetUserActiveStateSendOnLogin) {
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(5 * kSecondsPerDay + 10));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(5 * kSecondsPerDay + 10), daemon_.user_active_last_);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 20));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 20), daemon_.user_active_last_);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 120));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 120), daemon_.user_active_last_);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 100);

  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 220));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 220), daemon_.user_active_last_);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 200);

  ExpectDailyUseTimeMetric(/* sample */ 3);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(8 * kSecondsPerDay - 300));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(8 * kSecondsPerDay - 300), daemon_.user_active_last_);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());
}

TEST_F(MetricsDaemonTest, SetUserActiveStateSendOnMonitor) {
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(8 * kSecondsPerDay - 300));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(8 * kSecondsPerDay - 300), daemon_.user_active_last_);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(8 * kSecondsPerDay + 300));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(8 * kSecondsPerDay + 300), daemon_.user_active_last_);
  EXPECT_EQ(8, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 8, /* seconds */ 600);

  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(9 * kSecondsPerDay - 200));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(9 * kSecondsPerDay - 200), daemon_.user_active_last_);
  EXPECT_EQ(8, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 8, /* seconds */ 600);

  ExpectDailyUseTimeMetric(/* sample */ 10);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(9 * kSecondsPerDay + 200));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(9 * kSecondsPerDay + 200), daemon_.user_active_last_);
  EXPECT_EQ(9, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 9, /* seconds */ 400);
}

TEST_F(MetricsDaemonTest, SetUserActiveStateTimeJump) {
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 500));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 500), daemon_.user_active_last_);
  EXPECT_EQ(10, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 300));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 300), daemon_.user_active_last_);
  EXPECT_EQ(10, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 1000));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 1000), daemon_.user_active_last_);
  EXPECT_EQ(10, daemon_.daily_use_day_last_);
  EXPECT_TRUE(AssertNoOrEmptyUseRecordFile());
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
