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

#include <string>

#include <base/metrics/histogram_base.h>
#include <base/metrics/histogram_flattener.h>
#include <base/metrics/histogram_snapshot_manager.h>
#include <brillo/daemons/daemon.h>

#include "persistent_integer.h"
#include "uploader/crash_counters.h"
#include "uploader/metrics_log.h"
#include "uploader/proto/chrome_user_metrics_extension.pb.h"
#include "uploader/sender.h"
#include "uploader/system_profile_cache.h"

class SystemProfileSetter;

// Service responsible for uploading the metrics periodically to the server.
// This service works as a simple 2-state state-machine.
//
// The two states are the presence or not of a staged log.
// A staged log is a compressed protobuffer containing both the aggregated
// metrics and event and information about the client. (product,
// model_manifest_id, etc...).
//
// At regular intervals, the upload event will be triggered and the following
// will happen:
// * if a staged log is present:
//    The previous upload may have failed for various reason. We then retry to
//    upload the same log.
//    - if the upload is successful, we discard the log (therefore
//      transitioning back to no staged log)
//    - if the upload fails, we keep the log to try again later.
//
// * if no staged logs are present:
//    Take a snapshot of the aggregated metrics, save it to disk and try to send
//    it:
//    - if the upload succeeds, we discard the staged log (transitioning back
//      to the no staged log state)
//    - if the upload fails, we continue and will retry to upload later.
//
class UploadService : public base::HistogramFlattener, public brillo::Daemon {
 public:
  UploadService(const std::string& server,
                const base::TimeDelta& upload_interval,
                const base::FilePath& private_metrics_directory,
                const base::FilePath& shared_metrics_directory,
                const std::shared_ptr<CrashCounters> counters);

  // Initializes the upload service.
  int OnInit();

  // Starts a new log. The log needs to be regenerated after each successful
  // launch as it is destroyed when staging the log.
  void StartNewLog();

  // Event callback for handling MessageLoop events.
  void UploadEventCallback(const base::TimeDelta& interval);

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
  FRIEND_TEST(UploadServiceTest, UnknownCrashIgnored);
  FRIEND_TEST(UploadServiceTest, ValuesInConfigFileAreSent);

  // Initializes the upload service for testing.
  void InitForTest(SystemProfileSetter* setter);

  // If a staged log fails to upload more than kMaxFailedUpload times, it
  // will be discarded.
  static const int kMaxFailedUpload;

  // Resets the internal state.
  void Reset();

  // Returns true iff metrics reporting is enabled.
  bool AreMetricsEnabled();

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

  scoped_ptr<SystemProfileSetter> system_profile_setter_;
  base::HistogramSnapshotManager histogram_snapshot_manager_;
  scoped_ptr<Sender> sender_;
  chromeos_metrics::PersistentInteger failed_upload_count_;
  scoped_ptr<MetricsLog> current_log_;
  std::shared_ptr<CrashCounters> counters_;

  base::TimeDelta upload_interval_;

  base::FilePath consent_file_;
  base::FilePath staged_log_path_;

  bool testing_;
};

#endif  // METRICS_UPLOADER_UPLOAD_SERVICE_H_
