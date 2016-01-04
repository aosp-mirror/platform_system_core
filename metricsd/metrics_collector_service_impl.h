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

#ifndef METRICSD_METRICS_COLLECTOR_SERVICE_IMPL_H_
#define METRICSD_METRICS_COLLECTOR_SERVICE_IMPL_H_

// metrics_collector binder service implementation.  Constructed by
// MetricsCollector.

#include "android/brillo/metrics/BnMetricsCollectorService.h"

#include <binder/Status.h>

class MetricsCollector;

class BnMetricsCollectorServiceImpl
    : public android::brillo::metrics::BnMetricsCollectorService {
 public:
  // Passed a this pointer from the MetricsCollector object that constructs us.
  explicit BnMetricsCollectorServiceImpl(
      MetricsCollector* metrics_collector_service);

  virtual ~BnMetricsCollectorServiceImpl() = default;

  // Called by crash_reporter to report a userspace crash event.  We relay
  // this to MetricsCollector.
  android::binder::Status notifyUserCrash();

 private:
  // MetricsCollector object that constructs us, we use this to call back
  // to it.
  MetricsCollector* metrics_collector_;
};

#endif  // METRICSD_METRICS_COLLECTOR_SERVICE_IMPL_H_
