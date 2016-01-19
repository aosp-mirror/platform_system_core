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

#include "uploader/bn_metricsd_impl.h"

#include <base/metrics/histogram.h>
#include <base/metrics/sparse_histogram.h>
#include <base/metrics/statistics_recorder.h>
#include <utils/Errors.h>
#include <utils/String16.h>
#include <utils/String8.h>

using android::binder::Status;
using android::String16;

static const char16_t kCrashTypeKernel[] = u"kernel";
static const char16_t kCrashTypeUncleanShutdown[] = u"uncleanshutdown";
static const char16_t kCrashTypeUser[] = u"user";

BnMetricsdImpl::BnMetricsdImpl(const std::shared_ptr<CrashCounters>& counters)
    : counters_(counters) {
  CHECK(counters_) << "Invalid counters argument to constructor";
}

Status BnMetricsdImpl::recordHistogram(
    const String16& name, int sample, int min, int max, int nbuckets) {
  base::HistogramBase* histogram = base::Histogram::FactoryGet(
      android::String8(name).string(), min, max, nbuckets,
      base::Histogram::kUmaTargetedHistogramFlag);
  // |histogram| may be null if a client reports two contradicting histograms
  // with the same name but different limits.
  // FactoryGet will print a useful message if that is the case.
  if (histogram) {
    histogram->Add(sample);
  }
  return Status::ok();
}

Status BnMetricsdImpl::recordLinearHistogram(const String16& name,
                                             int sample,
                                             int max) {
  base::HistogramBase* histogram = base::LinearHistogram::FactoryGet(
      android::String8(name).string(), 1, max, max + 1,
      base::Histogram::kUmaTargetedHistogramFlag);
  // |histogram| may be null if a client reports two contradicting histograms
  // with the same name but different limits.
  // FactoryGet will print a useful message if that is the case.
  if (histogram) {
    histogram->Add(sample);
  }
  return Status::ok();
}

Status BnMetricsdImpl::recordSparseHistogram(const String16& name, int sample) {
  base::HistogramBase* histogram = base::SparseHistogram::FactoryGet(
      android::String8(name).string(),
      base::Histogram::kUmaTargetedHistogramFlag);
  // |histogram| may be null if a client reports two contradicting histograms
  // with the same name but different limits.
  // FactoryGet will print a useful message if that is the case.
  if (histogram) {
    histogram->Add(sample);
  }
  return Status::ok();
}

Status BnMetricsdImpl::recordCrash(const String16& type) {
  if (type == kCrashTypeUser) {
    counters_->IncrementUserCrashCount();
  } else if (type == kCrashTypeKernel) {
    counters_->IncrementKernelCrashCount();
  } else if (type == kCrashTypeUncleanShutdown) {
    counters_->IncrementUncleanShutdownCount();
  } else {
    LOG(ERROR) << "Unknown crash type received: " << type;
  }
  return Status::ok();
}

Status BnMetricsdImpl::getHistogramsDump(String16* dump) {
  std::string str_dump;
  base::StatisticsRecorder::WriteGraph(std::string(), &str_dump);
  *dump = String16(str_dump.c_str());
  return Status::ok();
}
