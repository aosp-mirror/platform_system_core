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

#include "metrics/timer.h"

#include <string>

#include "metrics/metrics_library.h"

namespace chromeos_metrics {

base::TimeTicks ClockWrapper::GetCurrentTime() const {
  return base::TimeTicks::Now();
}

Timer::Timer()
    : timer_state_(kTimerStopped),
      clock_wrapper_(new ClockWrapper()) {}

bool Timer::Start() {
  elapsed_time_ = base::TimeDelta();  // Sets elapsed_time_ to zero.
  start_time_ = clock_wrapper_->GetCurrentTime();
  timer_state_ = kTimerRunning;
  return true;
}

bool Timer::Stop() {
  if (timer_state_ == kTimerStopped)
    return false;
  if (timer_state_ == kTimerRunning)
    elapsed_time_ += clock_wrapper_->GetCurrentTime() - start_time_;
  timer_state_ = kTimerStopped;
  return true;
}

bool Timer::Pause() {
  switch (timer_state_) {
    case kTimerStopped:
      if (!Start())
        return false;
      timer_state_ = kTimerPaused;
      return true;
    case kTimerRunning:
      timer_state_ = kTimerPaused;
      elapsed_time_ += clock_wrapper_->GetCurrentTime() - start_time_;
      return true;
    default:
      return false;
  }
}

bool Timer::Resume() {
  switch (timer_state_) {
    case kTimerStopped:
      return Start();
    case kTimerPaused:
      start_time_ = clock_wrapper_->GetCurrentTime();
      timer_state_ = kTimerRunning;
      return true;
    default:
      return false;
  }
}

bool Timer::Reset() {
  elapsed_time_ = base::TimeDelta();  // Sets elapsed_time_ to zero.
  timer_state_ = kTimerStopped;
  return true;
}

bool Timer::HasStarted() const {
  return timer_state_ != kTimerStopped;
}

bool Timer::GetElapsedTime(base::TimeDelta* elapsed_time) const {
  if (start_time_.is_null() || !elapsed_time)
    return false;
  *elapsed_time = elapsed_time_;
  if (timer_state_ == kTimerRunning) {
    *elapsed_time += clock_wrapper_->GetCurrentTime() - start_time_;
  }
  return true;
}

// static
MetricsLibraryInterface* TimerReporter::metrics_lib_ = nullptr;

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
