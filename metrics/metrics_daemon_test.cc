// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics_daemon.h"

#include <sys/file.h>

#include <base/eintr_wrapper.h>
#include <base/file_util.h>
#include <base/logging.h>
#include <base/string_util.h>
#include <gtest/gtest.h>

static const char kTestDailyUseRecordFile[] = "/tmp/daily-usage-test";
static const char kDoesNotExistFile[] = "/does/not/exist";

static const int kSecondsPerDay = 24 * 60 * 60;

class MetricsDaemonTest : public testing::Test {
 protected:
  virtual void SetUp() {
    daemon_.Init(true);
    daemon_.daily_use_record_file_ = kTestDailyUseRecordFile;

    // The test fixture object will be used by the log message handler.
    daemon_test_ = this;
    logging::SetLogMessageHandler(LogMessageHandler);
  }

  virtual void TearDown() {
    logging::SetLogMessageHandler(NULL);
    daemon_test_ = NULL;
    file_util::Delete(FilePath(kTestDailyUseRecordFile), false);
  }

  // Collects log messages in the |daemon_log_| member string so that
  // they can be analyzed for errors and expected behavior.
  static bool LogMessageHandler(int severity, const std::string& str) {
    daemon_test_->daemon_log_.append(str);
    daemon_test_->daemon_log_.append("\n");

    // Returning true would mute the log.
    return false;
  }

  // Returns true if the daemon log contains |pattern|, false otherwise.
  bool LogContains(const std::string& pattern) {
    return daemon_log_.find(pattern) != std::string::npos;
  }

  // Resets the daemon log history to empty.
  void LogReset() {
    daemon_log_.clear();
  }

  // Returns true if the specified metric is found in the generated
  // log so far, false otherwise.
  bool AssertMetricGenerated(const std::string& name, int sample,
                             int min, int max, int buckets) {
    return LogContains(StringPrintf("received metric: %s %d %d %d %d",
                                    name.c_str(), sample, min, max, buckets));
  }

  // Returns true if the specified daily use time metric is found in
  // the generated log so far, false otherwise.
  bool AssertDailyUseTimeMetric(int sample) {
    return AssertMetricGenerated(
        MetricsDaemon::kMetricDailyUseTimeName, sample,
        MetricsDaemon::kMetricDailyUseTimeMin,
        MetricsDaemon::kMetricDailyUseTimeMax,
        MetricsDaemon::kMetricDailyUseTimeBuckets);
  }

  // Returns true if the specified time to network drop metric is
  // found in the generated log so far, false otherwise.
  bool AssertTimeToNetworkDropMetric(int sample) {
    return AssertMetricGenerated(
        MetricsDaemon::kMetricTimeToNetworkDropName, sample,
        MetricsDaemon::kMetricTimeToNetworkDropMin,
        MetricsDaemon::kMetricTimeToNetworkDropMax,
        MetricsDaemon::kMetricTimeToNetworkDropBuckets);
  }

  // Returns true if no metric can be found in the generated log so
  // far, false otherwise.
  bool NoMetricGenerated() {
    return !LogContains("received metric");
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

  bool NoOrEmptyUseRecordFile() {
    FilePath record_file(daemon_.daily_use_record_file_);
    int64 record_file_size;
    return !file_util::PathExists(record_file) ||
        (file_util::GetFileSize(record_file, &record_file_size) &&
         record_file_size == 0);
  }

  // Pointer to the current test fixture.
  static MetricsDaemonTest* daemon_test_;

  // The MetricsDaemon under test.
  MetricsDaemon daemon_;

  // The accumulated metrics daemon log.
  std::string daemon_log_;
};

// static
MetricsDaemonTest* MetricsDaemonTest::daemon_test_ = NULL;

TEST_F(MetricsDaemonTest, LogDailyUseRecord) {
  EXPECT_EQ(0, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.LogDailyUseRecord(/* day */ 5, /* seconds */ 120);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 120);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);

  daemon_.LogDailyUseRecord(/* day */ 5, /* seconds */ 0);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 120);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);

  daemon_.LogDailyUseRecord(/* day */ 5, /* seconds */ 240);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 360);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);

  EXPECT_TRUE(NoMetricGenerated());

  LogReset();
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 0);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());
  EXPECT_TRUE(AssertDailyUseTimeMetric(/* sample */ 6));
  EXPECT_EQ(6, daemon_.daily_use_day_last_);

  // Tests rounding use time to the closest minute.
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 90);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 90);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);

  LogReset();
  daemon_.LogDailyUseRecord(/* day */ 7, /* seconds */ 89);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 89);
  EXPECT_TRUE(AssertDailyUseTimeMetric(/* sample */ 2));
  EXPECT_EQ(7, daemon_.daily_use_day_last_);

  LogReset();
  daemon_.LogDailyUseRecord(/* day */ 6, /* seconds */ 15);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 15);
  EXPECT_TRUE(AssertDailyUseTimeMetric(/* sample */ 1));
  EXPECT_EQ(6, daemon_.daily_use_day_last_);

  // Checks that the daemon doesn't die badly if the file can't be
  // created.
  LogReset();
  daemon_.daily_use_record_file_ = kDoesNotExistFile;
  daemon_.LogDailyUseRecord(10, 20);
  EXPECT_TRUE(LogContains("Unable to open the daily use file: "
                          "No such file or directory"));
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  file_util::Delete(FilePath(kDoesNotExistFile), false);
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

TEST_F(MetricsDaemonTest, LookupScreenSaverState) {
  EXPECT_EQ(MetricsDaemon::kScreenSaverStateLocked,
            daemon_.LookupScreenSaverState("locked"));
  EXPECT_EQ(MetricsDaemon::kScreenSaverStateUnlocked,
            daemon_.LookupScreenSaverState("unlocked"));
  EXPECT_EQ(MetricsDaemon::kUnknownScreenSaverState,
            daemon_.LookupScreenSaverState("somestate"));
}

TEST_F(MetricsDaemonTest, LookupSessionState) {
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted,
            daemon_.LookupSessionState("started"));
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped,
            daemon_.LookupSessionState("stopped"));
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState,
            daemon_.LookupSessionState("somestate"));
}

TEST_F(MetricsDaemonTest, NetStateChanged) {
  EXPECT_EQ(MetricsDaemon::kUnknownNetworkState, daemon_.network_state_);
  EXPECT_EQ(0, daemon_.network_state_last_);
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);

  daemon_.NetStateChanged("online", /* now */ 10);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(10, daemon_.network_state_last_);

  EXPECT_TRUE(NoMetricGenerated());

  daemon_.NetStateChanged("offline", /* now */ 30);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(30, daemon_.network_state_last_);
  EXPECT_TRUE(AssertTimeToNetworkDropMetric(/* sample */ 20));

  LogReset();
  daemon_.NetStateChanged("online", /* now */ 60);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(60, daemon_.network_state_last_);

  daemon_.PowerStateChanged("mem", /* now */ 80);
  EXPECT_EQ(MetricsDaemon::kPowerStateMem, daemon_.power_state_);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(60, daemon_.network_state_last_);

  daemon_.NetStateChanged("offline", /* now */ 85);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(85, daemon_.network_state_last_);

  daemon_.NetStateChanged("somestate", /* now */ 90);
  EXPECT_EQ(MetricsDaemon::kUnknownNetworkState, daemon_.network_state_);
  EXPECT_EQ(90, daemon_.network_state_last_);

  daemon_.NetStateChanged("offline", /* now */ 95);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(95, daemon_.network_state_last_);

  daemon_.PowerStateChanged("on", /* now */ 100);
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(95, daemon_.network_state_last_);

  daemon_.NetStateChanged("online", /* now */ 105);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOnline, daemon_.network_state_);
  EXPECT_EQ(105, daemon_.network_state_last_);

  EXPECT_TRUE(NoMetricGenerated());

  daemon_.NetStateChanged("offline", /* now */ 108);
  EXPECT_EQ(MetricsDaemon::kNetworkStateOffline, daemon_.network_state_);
  EXPECT_EQ(108, daemon_.network_state_last_);
  EXPECT_TRUE(AssertTimeToNetworkDropMetric(/* sample */ 3));
}

TEST_F(MetricsDaemonTest, PowerStateChanged) {
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(0, daemon_.user_active_last_);
  EXPECT_EQ(0, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true, 7 * kSecondsPerDay + 15);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(7 * kSecondsPerDay + 15, daemon_.user_active_last_);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.PowerStateChanged("mem", 7 * kSecondsPerDay + 45);
  EXPECT_EQ(MetricsDaemon::kPowerStateMem, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(7 * kSecondsPerDay + 45, daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 30);

  daemon_.PowerStateChanged("on", 7 * kSecondsPerDay + 85);
  EXPECT_EQ(MetricsDaemon::kPowerStateOn, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(7 * kSecondsPerDay + 45, daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 30);

  daemon_.PowerStateChanged("otherstate", 7 * kSecondsPerDay + 185);
  EXPECT_EQ(MetricsDaemon::kUnknownPowerState, daemon_.power_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(7 * kSecondsPerDay + 185, daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 7, /* seconds */ 30);

  EXPECT_TRUE(NoMetricGenerated());
}

TEST_F(MetricsDaemonTest, PublishMetric) {
  daemon_.PublishMetric("Dummy.Metric", /* sample */ 3,
                        /* min */ 1, /* max */ 100, /* buckets */ 50);
  EXPECT_TRUE(AssertMetricGenerated("Dummy.Metric", 3, 1, 100, 50));
}

TEST_F(MetricsDaemonTest, ScreenSaverStateChanged) {
  EXPECT_EQ(MetricsDaemon::kUnknownScreenSaverState,
            daemon_.screensaver_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(0, daemon_.user_active_last_);
  EXPECT_EQ(0, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.ScreenSaverStateChanged("locked", 5 * kSecondsPerDay + 10);
  EXPECT_EQ(MetricsDaemon::kScreenSaverStateLocked,
            daemon_.screensaver_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(5 * kSecondsPerDay + 10, daemon_.user_active_last_);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.ScreenSaverStateChanged("unlocked", 5 * kSecondsPerDay + 100);
  EXPECT_EQ(MetricsDaemon::kScreenSaverStateUnlocked,
            daemon_.screensaver_state_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(5 * kSecondsPerDay + 100, daemon_.user_active_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.ScreenSaverStateChanged("otherstate", 5 * kSecondsPerDay + 300);
  EXPECT_EQ(MetricsDaemon::kUnknownScreenSaverState,
            daemon_.screensaver_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(5 * kSecondsPerDay + 300, daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 5, /* seconds */ 200);

  EXPECT_TRUE(NoMetricGenerated());
}

TEST_F(MetricsDaemonTest, SessionStateChanged) {
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(0, daemon_.user_active_last_);
  EXPECT_EQ(0, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.SessionStateChanged("started", 15 * kSecondsPerDay + 20);
  EXPECT_EQ(MetricsDaemon::kSessionStateStarted, daemon_.session_state_);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(15 * kSecondsPerDay + 20, daemon_.user_active_last_);
  EXPECT_EQ(15, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.SessionStateChanged("stopped", 15 * kSecondsPerDay + 150);
  EXPECT_EQ(MetricsDaemon::kSessionStateStopped, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(15 * kSecondsPerDay + 150, daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 15, /* seconds */ 130);

  daemon_.SessionStateChanged("otherstate", 15 * kSecondsPerDay + 300);
  EXPECT_EQ(MetricsDaemon::kUnknownSessionState, daemon_.session_state_);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(15 * kSecondsPerDay + 300, daemon_.user_active_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 15, /* seconds */ 130);

  EXPECT_TRUE(NoMetricGenerated());
}

TEST_F(MetricsDaemonTest, SetUserActiveState) {
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(0, daemon_.user_active_last_);
  EXPECT_EQ(0, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ false, 5 * kSecondsPerDay + 10);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(5 * kSecondsPerDay + 10, daemon_.user_active_last_);
  EXPECT_EQ(5, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true, 6 * kSecondsPerDay + 20);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(6 * kSecondsPerDay + 20, daemon_.user_active_last_);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());

  daemon_.SetUserActiveState(/* active */ true, 6 * kSecondsPerDay + 120);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(6 * kSecondsPerDay + 120, daemon_.user_active_last_);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 100);

  daemon_.SetUserActiveState(/* active */ false, 6 * kSecondsPerDay + 220);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(6 * kSecondsPerDay + 220, daemon_.user_active_last_);
  EXPECT_EQ(6, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 6, /* seconds */ 200);

  EXPECT_TRUE(NoMetricGenerated());

  LogReset();
  daemon_.SetUserActiveState(/* active */ true, 8 * kSecondsPerDay - 300);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(8 * kSecondsPerDay - 300, daemon_.user_active_last_);
  EXPECT_EQ(7, daemon_.daily_use_day_last_);
  EXPECT_TRUE(NoOrEmptyUseRecordFile());
  EXPECT_TRUE(AssertDailyUseTimeMetric(/* sample */ 3));

  LogReset();
  daemon_.SetUserActiveState(/* active */ false, 8 * kSecondsPerDay + 300);
  EXPECT_FALSE(daemon_.user_active_);
  EXPECT_EQ(8 * kSecondsPerDay + 300, daemon_.user_active_last_);
  EXPECT_EQ(8, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 8, /* seconds */ 600);

  daemon_.SetUserActiveState(/* active */ true, 9 * kSecondsPerDay - 400);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(9 * kSecondsPerDay - 400, daemon_.user_active_last_);
  EXPECT_EQ(8, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 8, /* seconds */ 600);

  EXPECT_TRUE(NoMetricGenerated());

  LogReset();
  daemon_.SetUserActiveState(/* active */ true, 9 * kSecondsPerDay + 400);
  EXPECT_TRUE(daemon_.user_active_);
  EXPECT_EQ(9 * kSecondsPerDay + 400, daemon_.user_active_last_);
  EXPECT_EQ(9, daemon_.daily_use_day_last_);
  EXPECT_PRED_FORMAT2(AssertDailyUseRecord, /* day */ 9, /* seconds */ 800);
  EXPECT_TRUE(AssertDailyUseTimeMetric(/* sample */ 10));
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
