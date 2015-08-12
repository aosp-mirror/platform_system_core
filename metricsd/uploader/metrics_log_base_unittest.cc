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

#include "uploader/metrics_log_base.h"

#include <string>

#include <base/metrics/bucket_ranges.h>
#include <base/metrics/sample_vector.h>
#include <gtest/gtest.h>

#include "uploader/proto/chrome_user_metrics_extension.pb.h"

namespace metrics {

namespace {

class TestMetricsLogBase : public MetricsLogBase {
 public:
  TestMetricsLogBase()
      : MetricsLogBase("client_id", 1, MetricsLogBase::ONGOING_LOG, "1.2.3.4") {
  }
  virtual ~TestMetricsLogBase() {}

  using MetricsLogBase::uma_proto;

 private:
  DISALLOW_COPY_AND_ASSIGN(TestMetricsLogBase);
};

}  // namespace

TEST(MetricsLogBaseTest, LogType) {
  MetricsLogBase log1("id", 0, MetricsLogBase::ONGOING_LOG, "1.2.3");
  EXPECT_EQ(MetricsLogBase::ONGOING_LOG, log1.log_type());

  MetricsLogBase log2("id", 0, MetricsLogBase::INITIAL_STABILITY_LOG, "1.2.3");
  EXPECT_EQ(MetricsLogBase::INITIAL_STABILITY_LOG, log2.log_type());
}

TEST(MetricsLogBaseTest, EmptyRecord) {
  MetricsLogBase log("totally bogus client ID", 137,
                     MetricsLogBase::ONGOING_LOG, "bogus version");
  log.set_hardware_class("sample-class");
  log.CloseLog();

  std::string encoded;
  log.GetEncodedLog(&encoded);

  // A couple of fields are hard to mock, so these will be copied over directly
  // for the expected output.
  metrics::ChromeUserMetricsExtension parsed;
  ASSERT_TRUE(parsed.ParseFromString(encoded));

  metrics::ChromeUserMetricsExtension expected;
  expected.set_client_id(5217101509553811875);  // Hashed bogus client ID
  expected.set_session_id(137);
  expected.mutable_system_profile()->set_build_timestamp(
      parsed.system_profile().build_timestamp());
  expected.mutable_system_profile()->set_app_version("bogus version");
  expected.mutable_system_profile()->mutable_hardware()->set_hardware_class(
      "sample-class");

  EXPECT_EQ(expected.SerializeAsString(), encoded);
}

TEST(MetricsLogBaseTest, HistogramBucketFields) {
  // Create buckets: 1-5, 5-7, 7-8, 8-9, 9-10, 10-11, 11-12.
  base::BucketRanges ranges(8);
  ranges.set_range(0, 1);
  ranges.set_range(1, 5);
  ranges.set_range(2, 7);
  ranges.set_range(3, 8);
  ranges.set_range(4, 9);
  ranges.set_range(5, 10);
  ranges.set_range(6, 11);
  ranges.set_range(7, 12);

  base::SampleVector samples(&ranges);
  samples.Accumulate(3, 1);   // Bucket 1-5.
  samples.Accumulate(6, 1);   // Bucket 5-7.
  samples.Accumulate(8, 1);   // Bucket 8-9. (7-8 skipped)
  samples.Accumulate(10, 1);  // Bucket 10-11. (9-10 skipped)
  samples.Accumulate(11, 1);  // Bucket 11-12.

  TestMetricsLogBase log;
  log.RecordHistogramDelta("Test", samples);

  const metrics::ChromeUserMetricsExtension* uma_proto = log.uma_proto();
  const metrics::HistogramEventProto& histogram_proto =
      uma_proto->histogram_event(uma_proto->histogram_event_size() - 1);

  // Buckets with samples: 1-5, 5-7, 8-9, 10-11, 11-12.
  // Should become: 1-/, 5-7, /-9, 10-/, /-12.
  ASSERT_EQ(5, histogram_proto.bucket_size());

  // 1-5 becomes 1-/ (max is same as next min).
  EXPECT_TRUE(histogram_proto.bucket(0).has_min());
  EXPECT_FALSE(histogram_proto.bucket(0).has_max());
  EXPECT_EQ(1, histogram_proto.bucket(0).min());

  // 5-7 stays 5-7 (no optimization possible).
  EXPECT_TRUE(histogram_proto.bucket(1).has_min());
  EXPECT_TRUE(histogram_proto.bucket(1).has_max());
  EXPECT_EQ(5, histogram_proto.bucket(1).min());
  EXPECT_EQ(7, histogram_proto.bucket(1).max());

  // 8-9 becomes /-9 (min is same as max - 1).
  EXPECT_FALSE(histogram_proto.bucket(2).has_min());
  EXPECT_TRUE(histogram_proto.bucket(2).has_max());
  EXPECT_EQ(9, histogram_proto.bucket(2).max());

  // 10-11 becomes 10-/ (both optimizations apply, omit max is prioritized).
  EXPECT_TRUE(histogram_proto.bucket(3).has_min());
  EXPECT_FALSE(histogram_proto.bucket(3).has_max());
  EXPECT_EQ(10, histogram_proto.bucket(3).min());

  // 11-12 becomes /-12 (last record must keep max, min is same as max - 1).
  EXPECT_FALSE(histogram_proto.bucket(4).has_min());
  EXPECT_TRUE(histogram_proto.bucket(4).has_max());
  EXPECT_EQ(12, histogram_proto.bucket(4).max());
}

}  // namespace metrics
