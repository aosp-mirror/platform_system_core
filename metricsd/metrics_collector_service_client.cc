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

#include "metrics/metrics_collector_service_client.h"

#include <base/logging.h>
#include <binder/IServiceManager.h>
#include <utils/String16.h>

#include "android/brillo/metrics/IMetricsCollectorService.h"

namespace {
const char kMetricsCollectorServiceName[] =
    "android.brillo.metrics.IMetricsCollectorService";
}

bool MetricsCollectorServiceClient::Init() {
  const android::String16 name(kMetricsCollectorServiceName);
  metrics_collector_service_ = android::interface_cast<
      android::brillo::metrics::IMetricsCollectorService>(
      android::defaultServiceManager()->checkService(name));

  if (metrics_collector_service_ == nullptr)
    LOG(ERROR) << "Unable to lookup service " << kMetricsCollectorServiceName;

  return metrics_collector_service_ != nullptr;
}

bool MetricsCollectorServiceClient::notifyUserCrash() {
  if (metrics_collector_service_ == nullptr)
    return false;

  metrics_collector_service_->notifyUserCrash();
  return true;
}
