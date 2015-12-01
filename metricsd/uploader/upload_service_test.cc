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

#include <gtest/gtest.h>

#include <base/at_exit.h>
#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <base/logging.h>
#include <base/sys_info.h>

#include "constants.h"
#include "metrics/metrics_library_mock.h"
#include "persistent_integer.h"
#include "serialization/metric_sample.h"
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

    base::FilePath private_dir = dir_.path().Append("private");
    base::FilePath shared_dir = dir_.path().Append("shared");

    EXPECT_TRUE(base::CreateDirectory(private_dir));
    EXPECT_TRUE(base::CreateDirectory(shared_dir));

    metrics_lib_.InitForTest(shared_dir);
    ASSERT_EQ(0, base::WriteFile(shared_dir.Append(metrics::kConsentFileName),
                                 "", 0));
    upload_service_.reset(
        new UploadService("", base::TimeDelta(), private_dir, shared_dir));

    upload_service_->sender_.reset(new SenderMock);
    upload_service_->InitForTest(new MockSystemProfileSetter);
    upload_service_->GatherHistograms();
    upload_service_->Reset();
  }

  scoped_ptr<metrics::MetricSample> Crash(const std::string& name) {
    return metrics::MetricSample::CrashSample(name);
  }

  void SetTestingProperty(const std::string& name, const std::string& value) {
    base::FilePath filepath =
        dir_.path().Append("etc/os-release.d").Append(name);
    ASSERT_TRUE(base::CreateDirectory(filepath.DirName()));
    ASSERT_EQ(
        value.size(),
        base::WriteFile(filepath, value.data(), value.size()));
  }

  base::ScopedTempDir dir_;
  scoped_ptr<UploadService> upload_service_;
  MetricsLibrary metrics_lib_;

  scoped_ptr<base::AtExitManager> exit_manager_;
};

// Tests that the right crash increments a values.
TEST_F(UploadServiceTest, LogUserCrash) {
  upload_service_->AddSample(*Crash("user").get());

  MetricsLog* log = upload_service_->current_log_.get();
  metrics::ChromeUserMetricsExtension* proto = log->uma_proto();

  EXPECT_EQ(1, proto->system_profile().stability().other_user_crash_count());
}

TEST_F(UploadServiceTest, LogUncleanShutdown) {
  upload_service_->AddSample(*Crash("uncleanshutdown"));

  EXPECT_EQ(1, upload_service_->current_log_
                   ->uma_proto()
                   ->system_profile()
                   .stability()
                   .unclean_system_shutdown_count());
}

TEST_F(UploadServiceTest, LogKernelCrash) {
  upload_service_->AddSample(*Crash("kernel"));

  EXPECT_EQ(1, upload_service_->current_log_
                   ->uma_proto()
                   ->system_profile()
                   .stability()
                   .kernel_crash_count());
}

TEST_F(UploadServiceTest, UnknownCrashIgnored) {
  upload_service_->AddSample(*Crash("foo"));

  // The log should be empty.
  EXPECT_FALSE(upload_service_->current_log_);
}

TEST_F(UploadServiceTest, FailedSendAreRetried) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  sender->set_should_succeed(false);

  upload_service_->AddSample(*Crash("user"));
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

  upload_service_->AddSample(*Crash("user"));

  for (int i = 0; i < UploadService::kMaxFailedUpload; i++) {
    upload_service_->UploadEvent();
  }

  EXPECT_TRUE(upload_service_->HasStagedLog());
  upload_service_->UploadEvent();
  EXPECT_FALSE(upload_service_->HasStagedLog());

  // Log a new sample. The failed upload counter should be reset.
  upload_service_->AddSample(*Crash("user"));
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
  UploadService upload_service("", base::TimeDelta(), dir_.path(), dir_.path());

  // current_log_ should be initialized later as it needs AtExitManager to exit
  // in order to gather system information from SysInfo.
  EXPECT_FALSE(upload_service.current_log_);
}

TEST_F(UploadServiceTest, CanSendMultipleTimes) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  upload_service_->AddSample(*Crash("user"));
  upload_service_->UploadEvent();

  std::string first_message = sender->last_message();

  upload_service_->AddSample(*Crash("kernel"));
  upload_service_->UploadEvent();

  EXPECT_NE(first_message, sender->last_message());
}

TEST_F(UploadServiceTest, LogEmptyAfterUpload) {
  upload_service_->AddSample(*Crash("user"));

  EXPECT_TRUE(upload_service_->current_log_);

  upload_service_->UploadEvent();
  EXPECT_FALSE(upload_service_->current_log_);
}

TEST_F(UploadServiceTest, LogContainsAggregatedValues) {
  scoped_ptr<metrics::MetricSample> histogram =
      metrics::MetricSample::HistogramSample("foo", 10, 0, 42, 10);
  upload_service_->AddSample(*histogram.get());

  scoped_ptr<metrics::MetricSample> histogram2 =
      metrics::MetricSample::HistogramSample("foo", 11, 0, 42, 10);
  upload_service_->AddSample(*histogram2.get());

  upload_service_->GatherHistograms();
  metrics::ChromeUserMetricsExtension* proto =
      upload_service_->current_log_->uma_proto();
  EXPECT_EQ(1, proto->histogram_event().size());
}

TEST_F(UploadServiceTest, ExtractChannelFromString) {
  EXPECT_EQ(
      SystemProfileCache::ProtoChannelFromString(
          "developer-build"),
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

  scoped_ptr<metrics::MetricSample> histogram =
      metrics::MetricSample::SparseHistogramSample("myhistogram", 1);
  // Reset to create the new log with the profile setter.
  upload_service_->system_profile_setter_.reset(
      new SystemProfileCache(true, dir_.path()));
  upload_service_->Reset();
  upload_service_->AddSample(*histogram.get());
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

// Test that we can log metrics from the metrics library and have the uploader
// upload them.
TEST_F(UploadServiceTest, LogFromTheMetricsLibrary) {
  SenderMock* sender = new SenderMock();
  upload_service_->sender_.reset(sender);

  upload_service_->UploadEvent();
  EXPECT_EQ(0, sender->send_call_count());

  metrics_lib_.SendEnumToUMA("testname", 2, 10);
  upload_service_->UploadEvent();

  EXPECT_EQ(1, sender->send_call_count());
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
