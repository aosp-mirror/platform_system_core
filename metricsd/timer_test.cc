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

#include <stdint.h>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <memory>

#include "metrics/metrics_library_mock.h"
#include "metrics/timer.h"
#include "metrics/timer_mock.h"

using ::testing::_;
using ::testing::Return;

namespace chromeos_metrics {

namespace {
const int64_t kStime1MSec = 1400;
const int64_t kEtime1MSec = 3000;
const int64_t kDelta1MSec = 1600;

const int64_t kStime2MSec = 4200;
const int64_t kEtime2MSec = 5000;
const int64_t kDelta2MSec = 800;

const int64_t kStime3MSec = 6600;
const int64_t kEtime3MSec = 6800;
const int64_t kDelta3MSec = 200;
}  // namespace

class TimerTest : public testing::Test {
 public:
  TimerTest() : clock_wrapper_mock_(new ClockWrapperMock()) {}

 protected:
  virtual void SetUp() {
    EXPECT_EQ(Timer::kTimerStopped, timer_.timer_state_);
    stime += base::TimeDelta::FromMilliseconds(kStime1MSec);
    etime += base::TimeDelta::FromMilliseconds(kEtime1MSec);
    stime2 += base::TimeDelta::FromMilliseconds(kStime2MSec);
    etime2 += base::TimeDelta::FromMilliseconds(kEtime2MSec);
    stime3 += base::TimeDelta::FromMilliseconds(kStime3MSec);
    etime3 += base::TimeDelta::FromMilliseconds(kEtime3MSec);
  }

  virtual void TearDown() {}

  Timer timer_;
  std::unique_ptr<ClockWrapperMock> clock_wrapper_mock_;
  base::TimeTicks stime, etime, stime2, etime2, stime3, etime3;
};

TEST_F(TimerTest, StartStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);

  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_FALSE(timer_.HasStarted());
}

TEST_F(TimerTest, ReStart) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  timer_.Start();
  base::TimeTicks buffer = timer_.start_time_;
  timer_.Start();
  ASSERT_FALSE(timer_.start_time_ == buffer);
}

TEST_F(TimerTest, Reset) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  timer_.Start();
  ASSERT_TRUE(timer_.Reset());
  ASSERT_FALSE(timer_.HasStarted());
}

TEST_F(TimerTest, SeparatedTimers) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime2);
  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta2MSec);
  ASSERT_FALSE(timer_.HasStarted());

  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, InvalidStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_FALSE(timer_.Stop());
  // Now we try it again, but after a valid start/stop.
  timer_.Start();
  timer_.Stop();
  base::TimeDelta elapsed_time = timer_.elapsed_time_;
  ASSERT_FALSE(timer_.Stop());
  ASSERT_TRUE(elapsed_time == timer_.elapsed_time_);
}

TEST_F(TimerTest, InvalidElapsedTime) {
  base::TimeDelta elapsed_time;
  ASSERT_FALSE(timer_.GetElapsedTime(&elapsed_time));
}

TEST_F(TimerTest, PauseStartStopResume) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2))
      .WillOnce(Return(stime3))
      .WillOnce(Return(etime3));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Pause());  // Starts timer paused.
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Start());  // Restarts timer.
  ASSERT_TRUE(timer_.start_time_ == stime2);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta2MSec);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(kDelta3MSec, elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, ResumeStartStopPause) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2))
      .WillOnce(Return(stime3));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime2);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta2MSec);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(0, elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_FALSE(timer_.Resume());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartPauseStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartPauseResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec + kDelta2MSec);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, PauseStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), 0);

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), 0);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, PauseResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta2MSec);
  ASSERT_FALSE(timer_.HasStarted());
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartPauseResumePauseStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(stime3))
      .WillOnce(Return(etime3));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());
  // Make sure GetElapsedTime works while we're running.
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(kDelta1MSec + kStime3MSec - kStime2MSec,
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            kDelta1MSec + kEtime3MSec - kStime2MSec);
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            kDelta1MSec + kEtime3MSec - kStime2MSec);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

TEST_F(TimerTest, StartPauseResumePauseResumeStop) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime))
      .WillOnce(Return(stime2))
      .WillOnce(Return(etime2))
      .WillOnce(Return(stime3))
      .WillOnce(Return(etime3));
  timer_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  ASSERT_TRUE(timer_.Start());
  ASSERT_TRUE(timer_.start_time_ == stime);
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec);
  base::TimeDelta elapsed_time;
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Pause());
  ASSERT_TRUE(timer_.HasStarted());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(), kDelta1MSec + kDelta2MSec);
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());

  ASSERT_TRUE(timer_.Resume());
  ASSERT_TRUE(timer_.HasStarted());

  ASSERT_TRUE(timer_.Stop());
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            kDelta1MSec + kDelta2MSec + kDelta3MSec);
  ASSERT_FALSE(timer_.HasStarted());
  ASSERT_TRUE(timer_.GetElapsedTime(&elapsed_time));
  ASSERT_EQ(timer_.elapsed_time_.InMilliseconds(),
            elapsed_time.InMilliseconds());
}

static const char kMetricName[] = "test-timer";
static const int kMinSample = 0;
static const int kMaxSample = 120 * 1E6;
static const int kNumBuckets = 50;

class TimerReporterTest : public testing::Test {
 public:
  TimerReporterTest() : timer_reporter_(kMetricName, kMinSample, kMaxSample,
                                        kNumBuckets),
                        clock_wrapper_mock_(new ClockWrapperMock()) {}

 protected:
  virtual void SetUp() {
    timer_reporter_.set_metrics_lib(&lib_);
    EXPECT_EQ(timer_reporter_.histogram_name_, kMetricName);
    EXPECT_EQ(timer_reporter_.min_, kMinSample);
    EXPECT_EQ(timer_reporter_.max_, kMaxSample);
    EXPECT_EQ(timer_reporter_.num_buckets_, kNumBuckets);
    stime += base::TimeDelta::FromMilliseconds(kStime1MSec);
    etime += base::TimeDelta::FromMilliseconds(kEtime1MSec);
  }

  virtual void TearDown() {
    timer_reporter_.set_metrics_lib(nullptr);
  }

  TimerReporter timer_reporter_;
  MetricsLibraryMock lib_;
  std::unique_ptr<ClockWrapperMock> clock_wrapper_mock_;
  base::TimeTicks stime, etime;
};

TEST_F(TimerReporterTest, StartStopReport) {
  EXPECT_CALL(*clock_wrapper_mock_, GetCurrentTime())
      .WillOnce(Return(stime))
      .WillOnce(Return(etime));
  timer_reporter_.clock_wrapper_.reset(clock_wrapper_mock_.release());
  EXPECT_CALL(lib_, SendToUMA(kMetricName, kDelta1MSec, kMinSample, kMaxSample,
                              kNumBuckets)).WillOnce(Return(true));
  ASSERT_TRUE(timer_reporter_.Start());
  ASSERT_TRUE(timer_reporter_.Stop());
  ASSERT_TRUE(timer_reporter_.ReportMilliseconds());
}

TEST_F(TimerReporterTest, InvalidReport) {
  ASSERT_FALSE(timer_reporter_.ReportMilliseconds());
}

}  // namespace chromeos_metrics

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
