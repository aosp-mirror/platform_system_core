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

// Client interface to IMetricsCollectorService.

#ifndef METRICS_METRICS_COLLECTOR_SERVICE_CLIENT_H_
#define METRICS_METRICS_COLLECTOR_SERVICE_CLIENT_H_

#include "android/brillo/metrics/IMetricsCollectorService.h"

class MetricsCollectorServiceClient {
 public:
  MetricsCollectorServiceClient() = default;
  ~MetricsCollectorServiceClient() = default;

  // Initialize.  Returns true if OK, or false if IMetricsCollectorService
  // is not registered.
  bool Init();

  // Called by crash_reporter to report a userspace crash event.  Returns
  // true if successfully called the IMetricsCollectorService method of the
  // same name, or false if the service was not registered at Init() time.
  bool notifyUserCrash();

 private:
  // IMetricsCollectorService binder proxy
  android::sp<android::brillo::metrics::IMetricsCollectorService>
      metrics_collector_service_;
};

#endif  // METRICS_METRICS_COLLECTOR_SERVICE_CLIENT_H_
