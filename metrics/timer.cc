// Copyright (c) 2011 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "timer.h"

#include <string>

#include <base/memory/scoped_ptr.h>
#include <base/time.h>

#include "metrics_library.h"

namespace chromeos_metrics {

base::TimeTicks ClockWrapper::GetCurrentTime() const {
  return base::TimeTicks::Now();
}

Timer::Timer()
    : is_started_(false),
      clock_wrapper_(new ClockWrapper()) {}

bool Timer::Start() {
  start_time_ = clock_wrapper_->GetCurrentTime();
  is_started_ = true;
  return true;
}

bool Timer::Stop() {
  // Check if the timer has been started.
  if (!is_started_) return false;
  is_started_ = false;
  elapsed_time_ = clock_wrapper_->GetCurrentTime() - start_time_;
  return true;
}

bool Timer::Reset() {
  is_started_ = false;
  return true;
}

bool Timer::HasStarted() const {
  return is_started_;
}

bool Timer::GetElapsedTime(base::TimeDelta* elapsed_time) const {
  if (start_time_.is_null() || !elapsed_time) return false;
  if (is_started_) {
    *elapsed_time = clock_wrapper_->GetCurrentTime() - start_time_;
  } else {
    *elapsed_time = elapsed_time_;
  }
  return true;
}

// static
MetricsLibraryInterface* TimerReporter::metrics_lib_ = NULL;

TimerReporter::TimerReporter(const std::string& histogram_name, int min,
                             int max, int num_buckets)
    : histogram_name_(histogram_name),
      min_(min),
      max_(max),
      num_buckets_(num_buckets) {}

bool TimerReporter::ReportMilliseconds() const {
  base::TimeDelta elapsed_time;
  if (!metrics_lib_ || !GetElapsedTime(&elapsed_time)) return false;
  return metrics_lib_->SendToUMA(histogram_name_,
                                 elapsed_time.InMilliseconds(),
                                 min_,
                                 max_,
                                 num_buckets_);
}

}  // namespace chromeos_metrics
