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

#ifndef METRICSD_UPLOADER_BN_METRICSD_IMPL_H_
#define METRICSD_UPLOADER_BN_METRICSD_IMPL_H_

#include "android/brillo/metrics/BnMetricsd.h"
#include "uploader/crash_counters.h"

class BnMetricsdImpl : public android::brillo::metrics::BnMetricsd {
 public:
  explicit BnMetricsdImpl(const std::shared_ptr<CrashCounters>& counters);
  virtual ~BnMetricsdImpl() = default;

  // Records a histogram.
  android::binder::Status recordHistogram(const android::String16& name,
                                          int sample,
                                          int min,
                                          int max,
                                          int nbuckets) override;

  // Records a linear histogram.
  android::binder::Status recordLinearHistogram(const android::String16& name,
                                                int sample,
                                                int max) override;

  // Records a sparse histogram.
  android::binder::Status recordSparseHistogram(const android::String16& name,
                                                int sample) override;

  // Records a crash.
  android::binder::Status recordCrash(const android::String16& type) override;

  // Returns a dump of the histograms aggregated in memory.
  android::binder::Status getHistogramsDump(android::String16* dump) override;

 private:
  std::shared_ptr<CrashCounters> counters_;
};

#endif  // METRICSD_UPLOADER_BN_METRICSD_IMPL_H_
