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
// MetricsCollectorServiceTrampoline, which we use to call back into
// MetricsCollector.  The trampoline isolates us from the -frtti code of
// metrics_collector / libbrillo.

#include "android/brillo/metrics/BnMetricsCollectorService.h"

#include <memory>

#include <binder/Status.h>
#include <brillo/binder_watcher.h>

class MetricsCollectorServiceTrampoline;

//#include "metrics_collector_service_trampoline.h"

class BnMetricsCollectorServiceImpl
    : public android::brillo::metrics::BnMetricsCollectorService {
 public:
  // Passed a this pointer from the MetricsCollectorServiceTrampoline
  // object that constructs us.
  explicit BnMetricsCollectorServiceImpl(
      MetricsCollectorServiceTrampoline* metrics_collector_service_trampoline);

  virtual ~BnMetricsCollectorServiceImpl() = default;

  // Starts the binder main loop.
  void Run();

  // Called by crash_reporter to report a userspace crash event.  We relay
  // this to MetricsCollector using the trampoline.
  android::binder::Status notifyUserCrash();

 private:
  // Trampoline object that constructs us, we use this to call MetricsCollector
  // methods via the trampoline.
  MetricsCollectorServiceTrampoline* metrics_collector_service_trampoline_;

  // BinderWatcher object we construct for handling Binder traffic
  std::unique_ptr<brillo::BinderWatcher> binder_watcher_;
};

#endif  // METRICSD_METRICS_COLLECTOR_SERVICE_IMPL_H_
