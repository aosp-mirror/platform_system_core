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

#include <memory>
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
#include "uploader/metrics_log.h"
#include "uploader/sender_http.h"
#include "uploader/system_profile_setter.h"

const int UploadService::kMaxFailedUpload = 10;

UploadService::UploadService(const std::string& server,
                             const base::TimeDelta& upload_interval,
                             const base::TimeDelta& disk_persistence_interval,
                             const base::FilePath& private_metrics_directory,
                             const base::FilePath& shared_metrics_directory)
    : brillo::Daemon(),
      histogram_snapshot_manager_(this),
      sender_(new HttpSender(server)),
      failed_upload_count_(metrics::kFailedUploadCountName,
                           private_metrics_directory),
      counters_(new CrashCounters),
      upload_interval_(upload_interval),
      disk_persistence_interval_(disk_persistence_interval),
      metricsd_service_runner_(counters_) {
  staged_log_path_ = private_metrics_directory.Append(metrics::kStagedLogName);
  saved_log_path_ = private_metrics_directory.Append(metrics::kSavedLogName);
  consent_file_ = shared_metrics_directory.Append(metrics::kConsentFileName);
}

void UploadService::LoadSavedLog() {
  if (base::PathExists(saved_log_path_)) {
    GetOrCreateCurrentLog()->LoadFromFile(saved_log_path_);
  }
}

int UploadService::OnInit() {
  brillo::Daemon::OnInit();

  base::StatisticsRecorder::Initialize();
  metricsd_service_runner_.Start();

  system_profile_setter_.reset(new SystemProfileCache());

  base::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&UploadService::UploadEventCallback, base::Unretained(this)),
      upload_interval_);

  base::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&UploadService::PersistEventCallback, base::Unretained(this)),
      disk_persistence_interval_);

  LoadSavedLog();

  return EX_OK;
}

void UploadService::OnShutdown(int* exit_code) {
  metricsd_service_runner_.Stop();
  PersistToDisk();
}

void UploadService::InitForTest(SystemProfileSetter* setter) {
  LoadSavedLog();
  system_profile_setter_.reset(setter);
}

void UploadService::StartNewLog() {
  current_log_.reset(new MetricsLog());
}

void UploadService::UploadEventCallback() {
  UploadEvent();

  base::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&UploadService::UploadEventCallback, base::Unretained(this)),
      upload_interval_);
}

void UploadService::PersistEventCallback() {
  PersistToDisk();

  base::MessageLoop::current()->PostDelayedTask(
      FROM_HERE,
      base::Bind(&UploadService::PersistEventCallback, base::Unretained(this)),
      disk_persistence_interval_);
}

void UploadService::PersistToDisk() {
  GatherHistograms();
  if (current_log_) {
    current_log_->SaveToFile(saved_log_path_);
  }
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

  // Previous upload successful, stage another log.
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

void UploadService::GatherHistograms() {
  base::StatisticsRecorder::Histograms histograms;
  base::StatisticsRecorder::GetHistograms(&histograms);

  histogram_snapshot_manager_.PrepareDeltas(
      base::Histogram::kNoFlags, base::Histogram::kUmaTargetedHistogramFlag);

  // Gather and reset the crash counters, shared with the binder threads.
  unsigned int kernel_crashes = counters_->GetAndResetKernelCrashCount();
  unsigned int unclean_shutdowns = counters_->GetAndResetUncleanShutdownCount();
  unsigned int user_crashes = counters_->GetAndResetUserCrashCount();

  // Only create a log if the counters have changed.
  if (kernel_crashes > 0 || unclean_shutdowns > 0 || user_crashes > 0) {
    GetOrCreateCurrentLog()->IncrementKernelCrashCount(kernel_crashes);
    GetOrCreateCurrentLog()->IncrementUncleanShutdownCount(unclean_shutdowns);
    GetOrCreateCurrentLog()->IncrementUserCrashCount(user_crashes);
  }
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

  std::unique_ptr<MetricsLog> staged_log;
  staged_log.swap(current_log_);
  staged_log->CloseLog();
  if (!staged_log->PopulateSystemProfile(system_profile_setter_.get())) {
    LOG(WARNING) << "Error while adding metadata to the log. Discarding the "
                 << "log.";
    return;
  }

  if (!base::DeleteFile(saved_log_path_, false)) {
    // There is a chance that we will upload the same metrics twice but, if we
    // are lucky, the backup should be overridden before that. In doubt, try not
    // to lose any metrics.
    LOG(ERROR) << "failed to delete the last backup of the current log.";
  }

  failed_upload_count_.Set(0);
  staged_log->SaveToFile(staged_log_path_);
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
