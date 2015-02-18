// Copyright 2014 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "metrics/uploader/upload_service.h"

#include <string>

#include <base/bind.h>
#include <base/logging.h>
#include <base/memory/scoped_vector.h>
#include <base/message_loop/message_loop.h>
#include <base/metrics/histogram.h>
#include <base/metrics/histogram_base.h>
#include <base/metrics/histogram_snapshot_manager.h>
#include <base/metrics/sparse_histogram.h>
#include <base/metrics/statistics_recorder.h>
#include <base/sha1.h>

#include "metrics/serialization/metric_sample.h"
#include "metrics/serialization/serialization_utils.h"
#include "metrics/uploader/metrics_log.h"
#include "metrics/uploader/sender_http.h"
#include "metrics/uploader/system_profile_cache.h"

const int UploadService::kMaxFailedUpload = 10;

UploadService::UploadService(SystemProfileSetter* setter,
                             MetricsLibraryInterface* metrics_lib,
                             const std::string& server)
    : system_profile_setter_(setter),
      metrics_lib_(metrics_lib),
      histogram_snapshot_manager_(this),
      sender_(new HttpSender(server)),
      testing_(false) {
}

UploadService::UploadService(SystemProfileSetter* setter,
                             MetricsLibraryInterface* metrics_lib,
                             const std::string& server,
                             bool testing)
    : UploadService(setter, metrics_lib, server) {
  testing_ = testing;
}

void UploadService::Init(const base::TimeDelta& upload_interval,
                         const std::string& metrics_file) {
  base::StatisticsRecorder::Initialize();
  metrics_file_ = metrics_file;

  if (!testing_) {
    base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
        base::Bind(&UploadService::UploadEventCallback,
                   base::Unretained(this),
                   upload_interval),
        upload_interval);
  }
}

void UploadService::StartNewLog() {
  CHECK(!staged_log_) << "the staged log should be discarded before starting "
                         "a new metrics log";
  MetricsLog* log = new MetricsLog();
  log->PopulateSystemProfile(system_profile_setter_.get());
  current_log_.reset(log);
}

void UploadService::UploadEventCallback(const base::TimeDelta& interval) {
  UploadEvent();

  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&UploadService::UploadEventCallback,
                 base::Unretained(this),
                 interval),
      interval);
}

void UploadService::UploadEvent() {
  if (staged_log_) {
    // Previous upload failed, retry sending the logs.
    SendStagedLog();
    return;
  }

  // Previous upload successful, reading metrics sample from the file.
  ReadMetrics();
  GatherHistograms();

  // No samples found. Exit to avoid sending an empty log.
  if (!current_log_)
    return;

  StageCurrentLog();
  SendStagedLog();
}

void UploadService::SendStagedLog() {
  CHECK(staged_log_) << "staged_log_ must exist to be sent";

  // If metrics are not enabled, discard the log and exit.
  if (!metrics_lib_->AreMetricsEnabled()) {
    LOG(INFO) << "Metrics disabled. Don't upload metrics samples.";
    staged_log_.reset();
    return;
  }

  std::string log_text;
  staged_log_->GetEncodedLog(&log_text);
  if (!sender_->Send(log_text, base::SHA1HashString(log_text))) {
    ++failed_upload_count_;
    if (failed_upload_count_ <= kMaxFailedUpload) {
      LOG(WARNING) << "log upload failed " << failed_upload_count_
                   << " times. It will be retried later.";
      return;
    }
    LOG(WARNING) << "log failed more than " << kMaxFailedUpload << " times.";
  } else {
    LOG(INFO) << "uploaded " << log_text.length() << " bytes";
  }
  // Discard staged log.
  staged_log_.reset();
}

void UploadService::Reset() {
  staged_log_.reset();
  current_log_.reset();
  failed_upload_count_ = 0;
}

void UploadService::ReadMetrics() {
  CHECK(!staged_log_)
      << "cannot read metrics until the old logs have been discarded";

  ScopedVector<metrics::MetricSample> vector;
  metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      metrics_file_, &vector);

  int i = 0;
  for (ScopedVector<metrics::MetricSample>::iterator it = vector.begin();
       it != vector.end(); it++) {
    metrics::MetricSample* sample = *it;
    AddSample(*sample);
    i++;
  }
  DLOG(INFO) << i << " samples read";
}

void UploadService::AddSample(const metrics::MetricSample& sample) {
  base::HistogramBase* counter;
  switch (sample.type()) {
    case metrics::MetricSample::CRASH:
      AddCrash(sample.name());
      break;
    case metrics::MetricSample::HISTOGRAM:
      counter = base::Histogram::FactoryGet(
          sample.name(), sample.min(), sample.max(), sample.bucket_count(),
          base::Histogram::kUmaTargetedHistogramFlag);
      counter->Add(sample.sample());
      break;
    case metrics::MetricSample::SPARSE_HISTOGRAM:
      counter = base::SparseHistogram::FactoryGet(
          sample.name(), base::HistogramBase::kUmaTargetedHistogramFlag);
      counter->Add(sample.sample());
      break;
    case metrics::MetricSample::LINEAR_HISTOGRAM:
      counter = base::LinearHistogram::FactoryGet(
          sample.name(),
          1,
          sample.max(),
          sample.max() + 1,
          base::Histogram::kUmaTargetedHistogramFlag);
      counter->Add(sample.sample());
      break;
    case metrics::MetricSample::USER_ACTION:
      GetOrCreateCurrentLog()->RecordUserAction(sample.name());
      break;
    default:
      break;
  }
}

void UploadService::AddCrash(const std::string& crash_name) {
  if (crash_name == "user") {
    GetOrCreateCurrentLog()->IncrementUserCrashCount();
  } else if (crash_name == "kernel") {
    GetOrCreateCurrentLog()->IncrementKernelCrashCount();
  } else if (crash_name == "uncleanshutdown") {
    GetOrCreateCurrentLog()->IncrementUncleanShutdownCount();
  } else {
    DLOG(ERROR) << "crash name unknown" << crash_name;
  }
}

void UploadService::GatherHistograms() {
  base::StatisticsRecorder::Histograms histograms;
  base::StatisticsRecorder::GetHistograms(&histograms);

  histogram_snapshot_manager_.PrepareDeltas(
      base::Histogram::kNoFlags, base::Histogram::kUmaTargetedHistogramFlag);
}

void UploadService::RecordDelta(const base::HistogramBase& histogram,
                                const base::HistogramSamples& snapshot) {
  GetOrCreateCurrentLog()->RecordHistogramDelta(histogram.histogram_name(),
                                                snapshot);
}

void UploadService::StageCurrentLog() {
  CHECK(!staged_log_)
      << "staged logs must be discarded before another log can be staged";

  if (!current_log_) return;

  staged_log_.swap(current_log_);
  staged_log_->CloseLog();
  failed_upload_count_ = 0;
}

MetricsLog* UploadService::GetOrCreateCurrentLog() {
  if (!current_log_) {
    StartNewLog();
  }
  return current_log_.get();
}
