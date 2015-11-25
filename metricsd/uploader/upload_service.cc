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

#include "uploader/upload_service.h"

#include <sysexits.h>

#include <string>

#include <base/bind.h>
#include <base/files/file_util.h>
#include <base/logging.h>
#include <base/memory/scoped_vector.h>
#include <base/message_loop/message_loop.h>
#include <base/metrics/histogram.h>
#include <base/metrics/histogram_base.h>
#include <base/metrics/histogram_snapshot_manager.h>
#include <base/metrics/sparse_histogram.h>
#include <base/metrics/statistics_recorder.h>
#include <base/sha1.h>

#include "constants.h"
#include "serialization/metric_sample.h"
#include "serialization/serialization_utils.h"
#include "uploader/metrics_log.h"
#include "uploader/sender_http.h"
#include "uploader/system_profile_setter.h"

const int UploadService::kMaxFailedUpload = 10;

UploadService::UploadService(const std::string& server,
                             const base::TimeDelta& upload_interval,
                             const base::FilePath& metrics_directory)
    : histogram_snapshot_manager_(this),
      sender_(new HttpSender(server)),
      failed_upload_count_(metrics::kFailedUploadCountName, metrics_directory),
      upload_interval_(upload_interval) {
  metrics_file_ = metrics_directory.Append(metrics::kMetricsEventsFileName);
  staged_log_path_ = metrics_directory.Append(metrics::kStagedLogName);
  consent_file_ = metrics_directory.Append(metrics::kConsentFileName);
}

int UploadService::OnInit() {
  base::StatisticsRecorder::Initialize();

  system_profile_setter_.reset(new SystemProfileCache());

  base::MessageLoop::current()->PostDelayedTask(FROM_HERE,
      base::Bind(&UploadService::UploadEventCallback,
                 base::Unretained(this),
                 upload_interval_),
      upload_interval_);
  return EX_OK;
}

void UploadService::InitForTest(SystemProfileSetter* setter) {
  base::StatisticsRecorder::Initialize();
  system_profile_setter_.reset(setter);
}

void UploadService::StartNewLog() {
  CHECK(!HasStagedLog()) << "the staged log should be discarded before "
                         << "starting a new metrics log";
  MetricsLog* log = new MetricsLog();
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
  // If the system shutdown or crashed while uploading a report, we may not have
  // deleted an old log.
  RemoveFailedLog();

  if (HasStagedLog()) {
    // Previous upload failed, retry sending the logs.
    SendStagedLog();
    return;
  }

  // Previous upload successful, reading metrics sample from the file.
  ReadMetrics();
  GatherHistograms();
  StageCurrentLog();

  // If a log is available for upload, upload it.
  if (HasStagedLog()) {
    SendStagedLog();
  }
}

void UploadService::SendStagedLog() {
  // If metrics are not enabled, discard the log and exit.
  if (!AreMetricsEnabled()) {
    LOG(INFO) << "Metrics disabled. Don't upload metrics samples.";
    base::DeleteFile(staged_log_path_, false);
    return;
  }

  std::string staged_log;
  CHECK(base::ReadFileToString(staged_log_path_, &staged_log));

  // Increase the failed count in case the daemon crashes while sending the log.
  failed_upload_count_.Add(1);

  if (!sender_->Send(staged_log, base::SHA1HashString(staged_log))) {
    LOG(WARNING) << "log failed to upload";
  } else {
    VLOG(1) << "uploaded " << staged_log.length() << " bytes";
    base::DeleteFile(staged_log_path_, false);
  }

  RemoveFailedLog();
}

void UploadService::Reset() {
  base::DeleteFile(staged_log_path_, false);
  current_log_.reset();
  failed_upload_count_.Set(0);
}

void UploadService::ReadMetrics() {
  CHECK(!HasStagedLog()) << "cannot read metrics until the old logs have been "
                         << "discarded";

  ScopedVector<metrics::MetricSample> vector;
  metrics::SerializationUtils::ReadAndTruncateMetricsFromFile(
      metrics_file_.value(), &vector);

  int i = 0;
  for (ScopedVector<metrics::MetricSample>::iterator it = vector.begin();
       it != vector.end(); it++) {
    metrics::MetricSample* sample = *it;
    AddSample(*sample);
    i++;
  }
  VLOG(1) << i << " samples read";
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
  // If we haven't logged anything since the last upload, don't upload an empty
  // report.
  if (!current_log_)
    return;

  scoped_ptr<MetricsLog> staged_log;
  staged_log.swap(current_log_);
  staged_log->CloseLog();
  if (!staged_log->PopulateSystemProfile(system_profile_setter_.get())) {
    LOG(WARNING) << "Error while adding metadata to the log. Discarding the "
                 << "log.";
    return;
  }
  std::string encoded_log;
  staged_log->GetEncodedLog(&encoded_log);

  failed_upload_count_.Set(0);
  if (static_cast<int>(encoded_log.size()) != base::WriteFile(
      staged_log_path_, encoded_log.data(), encoded_log.size())) {
    LOG(ERROR) << "failed to persist to " << staged_log_path_.value();
  }
}

MetricsLog* UploadService::GetOrCreateCurrentLog() {
  if (!current_log_) {
    StartNewLog();
  }
  return current_log_.get();
}

bool UploadService::HasStagedLog() {
  return base::PathExists(staged_log_path_);
}

void UploadService::RemoveFailedLog() {
  if (failed_upload_count_.Get() > kMaxFailedUpload) {
    LOG(INFO) << "log failed more than " << kMaxFailedUpload << " times.";
    CHECK(base::DeleteFile(staged_log_path_, false))
        << "failed to delete staged log at " << staged_log_path_.value();
    failed_upload_count_.Set(0);
  }
}

bool UploadService::AreMetricsEnabled() {
  return base::PathExists(consent_file_);
}

