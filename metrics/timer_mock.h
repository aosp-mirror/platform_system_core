// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef METRICS_TIMER_MOCK_H_
#define METRICS_TIMER_MOCK_H_


#include <string>

#include <base/basictypes.h>
#include <base/time.h>
#include <gmock/gmock.h>

#include "timer.h"

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
  MOCK_METHOD0(Start, bool());
  MOCK_METHOD0(Stop, bool());
  MOCK_METHOD0(Reset, bool());
  MOCK_CONST_METHOD0(HasStarted, bool());
  MOCK_CONST_METHOD0(GetElapsedTime, base::TimeDelta());
  MOCK_CONST_METHOD0(ReportMilliseconds, bool());
};

class ClockWrapperMock : public ClockWrapper {
 public:
  MOCK_CONST_METHOD0(GetCurrentTime, base::TimeTicks());
};

}  // namespace chromeos_metrics

#endif  // METRICS_TIMER_MOCK_H_
