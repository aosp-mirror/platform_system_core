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

#ifndef METRICS_TIMER_MOCK_H_
#define METRICS_TIMER_MOCK_H_

#include <string>

#include <gmock/gmock.h>

#include "metrics/timer.h"

namespace chromeos_metrics {

class TimerMock : public Timer {
 public:
  MOCK_METHOD0(Start, bool());
  MOCK_METHOD0(Stop, bool());
  MOCK_METHOD0(Reset, bool());
  MOCK_CONST_METHOD0(HasStarted, bool());
  MOCK_CONST_METHOD1(GetElapsedTime, bool(base::TimeDelta* elapsed_time));
};

class TimerReporterMock : public TimerReporter {
 public:
  TimerReporterMock() : TimerReporter("", 0, 0, 0) {}
  MOCK_METHOD0(Start, bool());
  MOCK_METHOD0(Stop, bool());
  MOCK_METHOD0(Reset, bool());
  MOCK_CONST_METHOD0(HasStarted, bool());
  MOCK_CONST_METHOD1(GetElapsedTime, bool(base::TimeDelta* elapsed_time));
  MOCK_CONST_METHOD0(ReportMilliseconds, bool());
  MOCK_CONST_METHOD0(histogram_name, std::string&());
  MOCK_CONST_METHOD0(min, int());
  MOCK_CONST_METHOD0(max, int());
  MOCK_CONST_METHOD0(num_buckets, int());
};

class ClockWrapperMock : public ClockWrapper {
 public:
  MOCK_CONST_METHOD0(GetCurrentTime, base::TimeTicks());
};

}  // namespace chromeos_metrics

#endif  // METRICS_TIMER_MOCK_H_
