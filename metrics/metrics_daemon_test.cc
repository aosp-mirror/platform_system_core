// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <gtest/gtest.h>

#include "counter_mock.h"
#include "metrics_daemon.h"
#include "metrics_library_mock.h"

using base::Time;
using base::TimeTicks;
using chromeos_metrics::TaggedCounterMock;
using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

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
    EXPECT_EQ(NULL, daemon_.daily_use_.get());
    daemon_.Init(true, &metrics_lib_);

    // Tests constructor initialization. Switches to mock counters.
    EXPECT_TRUE(NULL != daemon_.daily_use_.get());
    daily_use_ = new StrictMock<TaggedCounterMock>();
    daemon_.daily_use_.reset(daily_use_);  // Transfers ownership.
    EXPECT_FALSE(daemon_.user_active_);
    EXPECT_TRUE(daemon_.user_active_last_.is_null());
    EXPECT_EQ(MetricsDaemon::kUnknownNetworkState, daemon_.network_state_);
    EXPECT_TRUE(daemon_.network_state_last_.is_null());
    EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
    EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  }

  virtual void TearDown() {}

  // Adds a daily use aggregation counter expectation that the
  // specified tag/count update will be generated.
  void ExpectDailyUseUpdate(int tag, int count) {
    EXPECT_CALL(*daily_use_, Update(tag, count))
        .Times(1)
        .RetiresOnSaturation();
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

  // Converts from seconds to a Time object.
  Time TestTime(int64 seconds) {
    return Time::FromInternalValue(seconds * Time::kMicrosecondsPerSecond);
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

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;

  // Metrics library mock. It's a strict mock so that all unexpected
  // metric generation calls are marked as failures.
  StrictMock<MetricsLibraryMock> metrics_lib_;

  // Daily use time aggregation counter mock. It's a strict mock so
  // that all unexpected update calls are marked as failures. It's a
  // pointer so that it can replace the scoped_ptr allocated by the
  // daemon.
  StrictMock<TaggedCounterMock>* daily_use_;
};

TEST_F(MetricsDaemonTest, DailyUseReporter) {
  ExpectDailyUseTimeMetric(/* sample */ 2);
  MetricsDaemon::DailyUseReporter(&daemon_, /* tag */ 20, /* count */ 90);

  ExpectDailyUseTimeMetric(/* sample */ 1);
  MetricsDaemon::DailyUseReporter(&daemon_, /* tag */ 23, /* count */ 89);
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

  EXPECT_CALL(*daily_use_, Update(_, 0))
      .Times(1)
      .RetiresOnSaturation();
  msg = NewDBusSignalString("/",
                            "org.chromium.PowerManager",
                            "ScreenIsUnlocked",
                            "");
  EXPECT_FALSE(daemon_.user_active_);
  res = MetricsDaemon::MessageFilter(/* connection */ NULL, msg, &daemon_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(DBUS_HANDLER_RESULT_HANDLED, res);
  DeleteDBusMessage(msg);

  EXPECT_CALL(*daily_use_, Update(_, 0))
      .Times(1)
      .RetiresOnSaturation();
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
  ExpectDailyUseUpdate(7, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(7 * kSecondsPerDay + 15));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 15), daemon_.user_active_last_);

  ExpectDailyUseUpdate(7, 30);
  daemon_.PowerStateChanged("mem", TestTime(7 * kSecondsPerDay + 45));
  EXPECT_EQ(MetricsDaemon::kPowerStateMem, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);

  daemon_.PowerStateChanged("on", TestTime(7 * kSecondsPerDay + 85));
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 45), daemon_.user_active_last_);

  ExpectDailyUseUpdate(7, 0);
  daemon_.PowerStateChanged("otherstate", TestTime(7 * kSecondsPerDay + 185));
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(7 * kSecondsPerDay + 185), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SendMetric) {
  ExpectMetric("Dummy.Metric", 3, 1, 100, 50);
  daemon_.SendMetric("Dummy.Metric", /* sample */ 3,
                     /* min */ 1, /* max */ 100, /* buckets */ 50);
}

TEST_F(MetricsDaemonTest, SessionStateChanged) {
  ExpectDailyUseUpdate(15, 0);
  daemon_.SessionStateChanged("started", TestTime(15 * kSecondsPerDay + 20));
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 20), daemon_.user_active_last_);

  ExpectDailyUseUpdate(15, 130);
  daemon_.SessionStateChanged("stopped", TestTime(15 * kSecondsPerDay + 150));
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 150), daemon_.user_active_last_);

  ExpectDailyUseUpdate(15, 0);
  daemon_.SessionStateChanged("otherstate",
                              TestTime(15 * kSecondsPerDay + 300));
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(15 * kSecondsPerDay + 300), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SetUserActiveState) {
  ExpectDailyUseUpdate(5, 0);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(5 * kSecondsPerDay + 10));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(5 * kSecondsPerDay + 10), daemon_.user_active_last_);

  ExpectDailyUseUpdate(6, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 20));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 20), daemon_.user_active_last_);

  ExpectDailyUseUpdate(6, 100);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(6 * kSecondsPerDay + 120));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 120), daemon_.user_active_last_);

  ExpectDailyUseUpdate(6, 110);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 230));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 230), daemon_.user_active_last_);

  ExpectDailyUseUpdate(6, 0);
  daemon_.SetUserActiveState(/* active */ false,
                             TestTime(6 * kSecondsPerDay + 260));
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(TestTime(6 * kSecondsPerDay + 260), daemon_.user_active_last_);
}

TEST_F(MetricsDaemonTest, SetUserActiveStateTimeJump) {
  ExpectDailyUseUpdate(10, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 500));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 500), daemon_.user_active_last_);

  ExpectDailyUseUpdate(10, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 300));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 300), daemon_.user_active_last_);

  ExpectDailyUseUpdate(10, 0);
  daemon_.SetUserActiveState(/* active */ true,
                             TestTime(10 * kSecondsPerDay + 1000));
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(TestTime(10 * kSecondsPerDay + 1000), daemon_.user_active_last_);
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
