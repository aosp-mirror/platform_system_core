//
// Copyright (C) 2015 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef METRICS_CONSTANTS_H_
#define METRICS_CONSTANTS_H_

namespace metrics {
static const char kSharedMetricsDirectory[] = "/data/misc/metrics/";
static const char kMetricsdDirectory[] = "/data/misc/metricsd/";
static const char kMetricsCollectorDirectory[] =
    "/data/misc/metrics_collector/";
static const char kMetricsGUIDFileName[] = "Sysinfo.GUID";
static const char kMetricsServer[] = "https://clients4.google.com/uma/v2";
static const char kConsentFileName[] = "enabled";
static const char kStagedLogName[] = "staged_log";
static const char kSavedLogName[] = "saved_log";
static const char kFailedUploadCountName[] = "failed_upload_count";
static const char kDefaultVersion[] = "0.0.0.0";

// Build time properties name.
static const char kProductId[] = "product_id";
static const char kProductVersion[] = "product_version";

// Weave configuration.
static const char kWeaveConfigurationFile[] = "/system/etc/weaved/weaved.conf";
static const char kModelManifestId[] = "model_id";
}  // namespace metrics

#endif  // METRICS_CONSTANTS_H_
