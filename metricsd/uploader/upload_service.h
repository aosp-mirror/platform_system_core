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

#ifndef METRICS_UPLOADER_UPLOAD_SERVICE_H_
#define METRICS_UPLOADER_UPLOAD_SERVICE_H_

#include <memory>
#include <string>

#include <base/metrics/histogram_base.h>
#include <base/metrics/histogram_flattener.h>
#include <base/metrics/histogram_snapshot_manager.h>
#include <brillo/daemons/daemon.h>

#include "persistent_integer.h"
#include "uploader/crash_counters.h"
#include "uploader/metrics_log.h"
#include "uploader/metricsd_service_runner.h"
#include "uploader/proto/chrome_user_metrics_extension.pb.h"
#include "uploader/sender.h"
#include "uploader/system_profile_cache.h"

class SystemProfileSetter;

// Service responsible for backing up the currently aggregated metrics to disk
// and uploading them periodically to the server.
//
// A given metrics sample can be in one of three locations.
// * in-memory metrics: in memory aggregated metrics, waiting to be staged for
//   upload.
// * saved log: protobuf message, written to disk periodically and on shutdown
//   to make a backup of metrics data for uploading later.
// * staged log: protobuf message waiting to be uploaded.
//
// The service works as follows:
// On startup, we create the in-memory metrics from the saved log if it exists.
//
// Periodically (every |disk_persistence_interval_| seconds), we take a snapshot
// of the in-memory metrics and save them to disk.
//
// Periodically (every |upload_interval| seconds), we:
// * take a snapshot of the in-memory metrics and create the staged log
// * save the staged log to disk to avoid losing it if metricsd or the system
//   crashes between two uploads.
// * delete the last saved log: all the metrics contained in it are also in the
//   newly created staged log.
//
// On shutdown (SIGINT or SIGTERM), we save the in-memory metrics to disk.
//
// Note: the in-memory metrics can be stored in |current_log_| or
// base::StatisticsRecorder.
class UploadService : public base::HistogramFlattener, public brillo::Daemon {
 public:
  UploadService(const std::string& server,
                const base::TimeDelta& upload_interval,
                const base::TimeDelta& disk_persistence_interval,
                const base::FilePath& private_metrics_directory,
                const base::FilePath& shared_metrics_directory);

  // Initializes the upload service.
  int OnInit() override;

  // Cleans up the internal state before exiting.
  void OnShutdown(int* exit_code) override;

  // Starts a new log. The log needs to be regenerated after each successful
  // launch as it is destroyed when staging the log.
  void StartNewLog();

  // Saves the current metrics to a file.
  void PersistToDisk();

  // Triggers an upload event.
  void UploadEvent();

  // Sends the staged log.
  void SendStagedLog();

  // Implements inconsistency detection to match HistogramFlattener's
  // interface.
  void InconsistencyDetected(
      base::HistogramBase::Inconsistency problem) override {}
  void UniqueInconsistencyDetected(
      base::HistogramBase::Inconsistency problem) override {}
  void InconsistencyDetectedInLoggedCount(int amount) override {}

 private:
  friend class UploadServiceTest;

  FRIEND_TEST(UploadServiceTest, CanSendMultipleTimes);
  FRIEND_TEST(UploadServiceTest, CorruptedSavedLog);
  FRIEND_TEST(UploadServiceTest, CurrentLogSavedAndResumed);
  FRIEND_TEST(UploadServiceTest, DiscardLogsAfterTooManyFailedUpload);
  FRIEND_TEST(UploadServiceTest, EmptyLogsAreNotSent);
  FRIEND_TEST(UploadServiceTest, FailedSendAreRetried);
  FRIEND_TEST(UploadServiceTest, LogContainsAggregatedValues);
  FRIEND_TEST(UploadServiceTest, LogContainsCrashCounts);
  FRIEND_TEST(UploadServiceTest, LogEmptyAfterUpload);
  FRIEND_TEST(UploadServiceTest, LogEmptyByDefault);
  FRIEND_TEST(UploadServiceTest, LogFromTheMetricsLibrary);
  FRIEND_TEST(UploadServiceTest, LogKernelCrash);
  FRIEND_TEST(UploadServiceTest, LogUncleanShutdown);
  FRIEND_TEST(UploadServiceTest, LogUserCrash);
  FRIEND_TEST(UploadServiceTest, PersistEmptyLog);
  FRIEND_TEST(UploadServiceTest, UnknownCrashIgnored);
  FRIEND_TEST(UploadServiceTest, ValuesInConfigFileAreSent);

  // Initializes the upload service for testing.
  void InitForTest(SystemProfileSetter* setter);

  // If a staged log fails to upload more than kMaxFailedUpload times, it
  // will be discarded.
  static const int kMaxFailedUpload;

  // Loads the log saved to disk if it exists.
  void LoadSavedLog();

  // Resets the internal state.
  void Reset();

  // Returns true iff metrics reporting is enabled.
  bool AreMetricsEnabled();

  // Event callback for handling Upload events.
  void UploadEventCallback();

  // Event callback for handling Persist events.
  void PersistEventCallback();

  // Aggregates all histogram available in memory and store them in the current
  // log.
  void GatherHistograms();

  // Callback for HistogramSnapshotManager to store the histograms.
  void RecordDelta(const base::HistogramBase& histogram,
                   const base::HistogramSamples& snapshot) override;

  // Compiles all the samples received into a single protobuf and adds all
  // system information.
  void StageCurrentLog();

  // Returns true iff a log is staged.
  bool HasStagedLog();

  // Remove the staged log iff the upload failed more than |kMaxFailedUpload|.
  void RemoveFailedLog();

  // Returns the current log. If there is no current log, creates it first.
  MetricsLog* GetOrCreateCurrentLog();

  std::unique_ptr<SystemProfileSetter> system_profile_setter_;
  base::HistogramSnapshotManager histogram_snapshot_manager_;
  std::unique_ptr<Sender> sender_;
  chromeos_metrics::PersistentInteger failed_upload_count_;
  std::unique_ptr<MetricsLog> current_log_;
  std::shared_ptr<CrashCounters> counters_;

  base::TimeDelta upload_interval_;
  base::TimeDelta disk_persistence_interval_;

  MetricsdServiceRunner metricsd_service_runner_;

  base::FilePath consent_file_;
  base::FilePath staged_log_path_;
  base::FilePath saved_log_path_;

  bool testing_;
};

#endif  // METRICS_UPLOADER_UPLOAD_SERVICE_H_
