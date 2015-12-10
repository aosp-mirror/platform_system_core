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

#ifndef METRICSD_METRICS_COLLECTOR_SERVICE_TRAMPOLINE_H_
#define METRICSD_METRICS_COLLECTOR_SERVICE_TRAMPOLINE_H_

// Trampoline between the -fno-rtti compile of libmetricsservice and the
// -frtti compile of metrics_collector.  MetricsCollectorServiceTrampoline
// is called from MetricsCollector to run the IMetricsCollectorService
// server, and acts as a go-between for calls from server back to
// MetricsCollector.

#include <memory>

#include "metrics_collector_service_impl.h"

// Forward declaration of MetricsCollector.  Don't include the header file
// for the class here, as it pulls in -frtti stuff.
class MetricsCollector;

class MetricsCollectorServiceTrampoline {
 public:
  // Constructor take a this pointer from the MetricsCollector class that
  // constructs these objects.
  explicit MetricsCollectorServiceTrampoline(
      MetricsCollector* metrics_collector);

  // Initialize and run the IMetricsCollectorService
  void Run();

  // Called from IMetricsCollectorService to trampoline into the
  // MetricsCollector method of the same name.
  void ProcessUserCrash();

 private:
  // The MetricsCollector object that constructs us, for which we act as
  // the go-between for MetricsCollectorServiceImpl use.
  MetricsCollector* metrics_collector_;

  // The IMetricsCollectorService implementation we construct.
  std::unique_ptr<BnMetricsCollectorServiceImpl> metrics_collector_service;
};

#endif  // METRICSD_METRICS_COLLECTOR_SERVICE_TRAMPOLINE_H_
