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

#include <memory>

#include <base/at_exit.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/metrics/sparse_histogram.h>
#include <base/metrics/statistics_recorder.h>
#include <base/sys_info.h>
#include <gtest/gtest.h>

#include "constants.h"
#include "persistent_integer.h"
#include "uploader/metrics_log.h"
#include "uploader/mock/mock_system_profile_setter.h"
#include "uploader/mock/sender_mock.h"
#include "uploader/proto/chrome_user_metrics_extension.pb.h"
#include "uploader/proto/histogram_event.pb.h"
#include "uploader/proto/system_profile.pb.h"
#include "uploader/system_profile_cache.h"
#include "uploader/upload_service.h"

class UploadServiceTest : public testing::Test {
 protected:
  virtual void SetUp() {
    CHECK(dir_.CreateUniqueTempDir());
    // Make sure the statistics recorder is inactive (contains no metrics) then
    // initialize it.
    ASSERT_FALSE(base::StatisticsRecorder::IsActive());
    base::StatisticsRecorder::Initialize();

    private_dir_ = dir_.path().Append("private");
    shared_dir_ = dir_.path().Append("shared");

    EXPECT_TRUE(base::CreateDirectory(private_dir_));
    EXPECT_TRUE(base::CreateDirectory(shared_dir_));

    ASSERT_EQ(0, base::WriteFile(shared_dir_.Append(metrics::kConsentFileName),
                                 "", 0));

    upload_service_.reset(new UploadService(
        "", base::TimeDelta(), base::TimeDelta(), private_dir_, shared_dir_));
    counters_ = upload_service_->counters_;

    upload_service_->sender_.reset(new SenderMock);
    upload_service_->InitForTest(new MockSystemProfileSetter);
    upload_service_->GatherHistograms();
    upload_service_->Reset();
  }

  void SendSparseHistogram(const std::string& name, int sample) {
    base::HistogramBase* histogram = base::SparseHistogram::FactoryGet(
        name, base::Histogram::kUmaTargetedHistogramFlag);
    histogram->Add(sample);
  }

  void SendHistogram(
      const std::string& name, int sample, int min, int max, int nbuckets) {
    base::HistogramBase* histogram = base::Histogram::FactoryGet(
        name, min, max, nbuckets, base::Histogram::kUmaTargetedHistogramFlag);
    histogram->Add(sample);
  }

  void SetTestingProperty(const std::string& name, const std::string& value) {
    base::FilePath filepath =
        dir_.path().Append("etc/os-release.d").Append(name);
    ASSERT_TRUE(base::CreateDirectory(filepath.DirName()));
    ASSERT_EQ(value.size(),
              base::WriteFile(filepath, value.data(), value.size()));
  }

  const metrics::SystemProfileProto_Stability GetCurrentStability() {
    EXPECT_TRUE(upload_service_->current_log_.get());

    return upload_service_->current_log_->uma_proto()
        ->system_profile()
        .stability();
  }

  base::ScopedTempDir dir_;
  std::unique_ptr<UploadService> upload_service_;

  std::unique_ptr<base::AtExitManager> exit_manager_;
  std::shared_ptr<CrashCounters> counters_;
  base::FilePath private_dir_;
  base::FilePath shared_dir_;
};

TEST_F(UploadServiceTest, FailedSendAreRetried) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  sender->set_should_succeed(false);

  SendSparseHistogram("hello", 1);
  upload_service_->UploadEvent();
  EXPECT_EQ(1, sender->send_call_count());
  std::string sent_string = sender->last_message();

  upload_service_->UploadEvent();
  EXPECT_EQ(2, sender->send_call_count());
  EXPECT_EQ(sent_string, sender->last_message());
}

TEST_F(UploadServiceTest, DiscardLogsAfterTooManyFailedUpload) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  sender->set_should_succeed(false);

  SendSparseHistogram("hello", 1);

  for (int i = 0; i < UploadService::kMaxFailedUpload; i++) {
    upload_service_->UploadEvent();
  }

  EXPECT_TRUE(upload_service_->HasStagedLog());
  upload_service_->UploadEvent();
  EXPECT_FALSE(upload_service_->HasStagedLog());

  // Log a new sample. The failed upload counter should be reset.
  SendSparseHistogram("hello", 1);
  for (int i = 0; i < UploadService::kMaxFailedUpload; i++) {
    upload_service_->UploadEvent();
  }
  // The log is not discarded after multiple failed uploads.
  EXPECT_TRUE(upload_service_->HasStagedLog());
}

TEST_F(UploadServiceTest, EmptyLogsAreNotSent) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);
  upload_service_->UploadEvent();
  EXPECT_FALSE(upload_service_->current_log_);
  EXPECT_EQ(0, sender->send_call_count());
}

TEST_F(UploadServiceTest, LogEmptyByDefault) {
  // current_log_ should be initialized later as it needs AtExitManager to exist
  // in order to gather system information from SysInfo.
  EXPECT_FALSE(upload_service_->current_log_);
}

TEST_F(UploadServiceTest, CanSendMultipleTimes) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  SendSparseHistogram("hello", 1);

  upload_service_->UploadEvent();

  std::string first_message = sender->last_message();
  SendSparseHistogram("hello", 2);

  upload_service_->UploadEvent();

  EXPECT_NE(first_message, sender->last_message());
}

TEST_F(UploadServiceTest, LogEmptyAfterUpload) {
  SendSparseHistogram("hello", 2);

  upload_service_->UploadEvent();
  EXPECT_FALSE(upload_service_->current_log_);
}

TEST_F(UploadServiceTest, LogContainsAggregatedValues) {
  SendHistogram("foo", 11, 0, 42, 10);
  SendHistogram("foo", 12, 0, 42, 10);

  upload_service_->GatherHistograms();
  metrics::ChromeUserMetricsExtension* proto =
      upload_service_->current_log_->uma_proto();
  EXPECT_EQ(1, proto->histogram_event().size());
}

TEST_F(UploadServiceTest, LogContainsCrashCounts) {
  // By default, there is no current log.
  upload_service_->GatherHistograms();
  EXPECT_FALSE(upload_service_->current_log_);

  // If the user crash counter is incremented, we add the count to the current
  // log.
  counters_->IncrementUserCrashCount();
  upload_service_->GatherHistograms();
  EXPECT_EQ(1, GetCurrentStability().other_user_crash_count());

  // If the kernel crash counter is incremented, we add the count to the current
  // log.
  counters_->IncrementKernelCrashCount();
  upload_service_->GatherHistograms();
  EXPECT_EQ(1, GetCurrentStability().kernel_crash_count());

  // If the kernel crash counter is incremented, we add the count to the current
  // log.
  counters_->IncrementUncleanShutdownCount();
  counters_->IncrementUncleanShutdownCount();
  upload_service_->GatherHistograms();
  EXPECT_EQ(2, GetCurrentStability().unclean_system_shutdown_count());

  // If no counter is incremented, the reported numbers don't change.
  upload_service_->GatherHistograms();
  EXPECT_EQ(1, GetCurrentStability().other_user_crash_count());
  EXPECT_EQ(1, GetCurrentStability().kernel_crash_count());
  EXPECT_EQ(2, GetCurrentStability().unclean_system_shutdown_count());
}

TEST_F(UploadServiceTest, ExtractChannelFromString) {
  EXPECT_EQ(SystemProfileCache::ProtoChannelFromString("developer-build"),
            metrics::SystemProfileProto::CHANNEL_UNKNOWN);

  EXPECT_EQ(metrics::SystemProfileProto::CHANNEL_DEV,
            SystemProfileCache::ProtoChannelFromString("dev-channel"));

  EXPECT_EQ(metrics::SystemProfileProto::CHANNEL_STABLE,
            SystemProfileCache::ProtoChannelFromString("stable-channel"));

  EXPECT_EQ(metrics::SystemProfileProto::CHANNEL_UNKNOWN,
            SystemProfileCache::ProtoChannelFromString("this is a test"));
}

TEST_F(UploadServiceTest, ValuesInConfigFileAreSent) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  SetTestingProperty(metrics::kProductId, "hello");
  SetTestingProperty(metrics::kProductVersion, "1.2.3.4");

  SendSparseHistogram("hello", 1);

  // Reset to create the new log with the profile setter.
  upload_service_->system_profile_setter_.reset(
      new SystemProfileCache(true, dir_.path()));
  upload_service_->Reset();
  upload_service_->UploadEvent();

  EXPECT_EQ(1, sender->send_call_count());
  EXPECT_TRUE(sender->is_good_proto());
  EXPECT_EQ(1, sender->last_message_proto().histogram_event().size());

  EXPECT_NE(0, sender->last_message_proto().client_id());
  EXPECT_NE(0, sender->last_message_proto().system_profile().build_timestamp());
  EXPECT_NE(0, sender->last_message_proto().session_id());
}

TEST_F(UploadServiceTest, PersistentGUID) {
  std::string tmp_file = dir_.path().Append("tmpfile").value();

  std::string first_guid = SystemProfileCache::GetPersistentGUID(tmp_file);
  std::string second_guid = SystemProfileCache::GetPersistentGUID(tmp_file);

  // The GUID are cached.
  EXPECT_EQ(first_guid, second_guid);

  base::DeleteFile(base::FilePath(tmp_file), false);

  first_guid = SystemProfileCache::GetPersistentGUID(tmp_file);
  base::DeleteFile(base::FilePath(tmp_file), false);
  second_guid = SystemProfileCache::GetPersistentGUID(tmp_file);

  // Random GUIDs are generated (not all the same).
  EXPECT_NE(first_guid, second_guid);
}

TEST_F(UploadServiceTest, SessionIdIncrementedAtInitialization) {
  SetTestingProperty(metrics::kProductId, "hello");
  SystemProfileCache cache(true, dir_.path());
  cache.Initialize();
  int session_id = cache.profile_.session_id;
  cache.initialized_ = false;
  cache.Initialize();
  EXPECT_EQ(cache.profile_.session_id, session_id + 1);
}

// The product id must be set for metrics to be uploaded.
// If it is not set, the system profile cache should fail to initialize.
TEST_F(UploadServiceTest, ProductIdMandatory) {
  SystemProfileCache cache(true, dir_.path());
  ASSERT_FALSE(cache.Initialize());
  SetTestingProperty(metrics::kProductId, "");
  ASSERT_FALSE(cache.Initialize());
  SetTestingProperty(metrics::kProductId, "hello");
  ASSERT_TRUE(cache.Initialize());
}

TEST_F(UploadServiceTest, CurrentLogSavedAndResumed) {
  SendHistogram("hello", 10, 0, 100, 10);
  upload_service_->PersistToDisk();
  EXPECT_EQ(
      1, upload_service_->current_log_->uma_proto()->histogram_event().size());
  upload_service_.reset(new UploadService(
      "", base::TimeDelta(), base::TimeDelta(), private_dir_, shared_dir_));
  upload_service_->InitForTest(nullptr);

  SendHistogram("hello", 10, 0, 100, 10);
  upload_service_->GatherHistograms();
  EXPECT_EQ(2, upload_service_->GetOrCreateCurrentLog()
                   ->uma_proto()
                   ->histogram_event()
                   .size());
}

TEST_F(UploadServiceTest, PersistEmptyLog) {
  upload_service_->PersistToDisk();
  EXPECT_FALSE(base::PathExists(upload_service_->saved_log_path_));
}

TEST_F(UploadServiceTest, CorruptedSavedLog) {
  // Write a bogus saved log.
  EXPECT_EQ(5, base::WriteFile(upload_service_->saved_log_path_, "hello", 5));

  upload_service_.reset(new UploadService(
      "", base::TimeDelta(), base::TimeDelta(), private_dir_, shared_dir_));

  upload_service_->InitForTest(nullptr);
  // If the log is unreadable, we drop it and continue execution.
  ASSERT_NE(nullptr, upload_service_->GetOrCreateCurrentLog());
  ASSERT_FALSE(base::PathExists(upload_service_->saved_log_path_));
}
