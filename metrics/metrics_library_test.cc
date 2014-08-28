// Copyright (c) 2010 The Chromium OS Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstring>

#include <base/file_util.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <policy/mock_device_policy.h>
#include <policy/libpolicy.h>

#include "metrics/c_metrics_library.h"
#include "metrics/metrics_library.h"

using base::FilePath;
using ::testing::_;
using ::testing::Return;
using ::testing::AnyNumber;

static const FilePath kTestUMAEventsFile("test-uma-events");
static const char kTestMounts[] = "test-mounts";

ACTION_P(SetMetricsPolicy, enabled) {
  *arg0 = enabled;
  return true;
}

class MetricsLibraryTest : public testing::Test {
 protected:
  virtual void SetUp() {
    EXPECT_TRUE(lib_.uma_events_file_.empty());
    lib_.Init();
    EXPECT_FALSE(lib_.uma_events_file_.empty());
    lib_.uma_events_file_ = kTestUMAEventsFile.value();
    EXPECT_EQ(0, WriteFile(kTestUMAEventsFile, "", 0));
    device_policy_ = new policy::MockDevicePolicy();
    EXPECT_CALL(*device_policy_, LoadPolicy())
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
        .Times(AnyNumber())
        .WillRepeatedly(SetMetricsPolicy(true));
    provider_ = new policy::PolicyProvider(device_policy_);
    lib_.SetPolicyProvider(provider_);
    // Defeat metrics enabled caching between tests.
    lib_.cached_enabled_time_ = 0;
  }

  virtual void TearDown() {
    base::DeleteFile(FilePath(kTestMounts), false);
    base::DeleteFile(kTestUMAEventsFile, false);
  }

  void VerifyEnabledCacheHit(bool to_value);
  void VerifyEnabledCacheEviction(bool to_value);

  MetricsLibrary lib_;
  policy::MockDevicePolicy* device_policy_;
  policy::PolicyProvider* provider_;
};

TEST_F(MetricsLibraryTest, IsDeviceMounted) {
  static const char kTestContents[] =
      "0123456789abcde 0123456789abcde\nguestfs foo bar\n";
  char buffer[1024];
  int block_sizes[] = { 1, 2, 3, 4, 5, 6, 8, 12, 14, 16, 32, 1024 };
  bool result;
  EXPECT_FALSE(lib_.IsDeviceMounted("guestfs",
                                    "nonexistent",
                                    buffer,
                                    1,
                                    &result));
  ASSERT_TRUE(base::WriteFile(base::FilePath(kTestMounts),
                              kTestContents,
                              strlen(kTestContents)));
  EXPECT_FALSE(lib_.IsDeviceMounted("guestfs",
                                    kTestMounts,
                                    buffer,
                                    0,
                                    &result));
  for (size_t i = 0; i < arraysize(block_sizes); ++i) {
    EXPECT_TRUE(lib_.IsDeviceMounted("0123456789abcde",
                                     kTestMounts,
                                     buffer,
                                     block_sizes[i],
                                     &result));
    EXPECT_TRUE(result);
    EXPECT_TRUE(lib_.IsDeviceMounted("guestfs",
                                     kTestMounts,
                                     buffer,
                                     block_sizes[i],
                                     &result));
    EXPECT_TRUE(result);
    EXPECT_TRUE(lib_.IsDeviceMounted("0123456",
                                     kTestMounts,
                                     buffer,
                                     block_sizes[i],
                                     &result));
    EXPECT_FALSE(result);
    EXPECT_TRUE(lib_.IsDeviceMounted("9abcde",
                                     kTestMounts,
                                     buffer,
                                     block_sizes[i],
                                     &result));
    EXPECT_FALSE(result);
    EXPECT_TRUE(lib_.IsDeviceMounted("foo",
                                     kTestMounts,
                                     buffer,
                                     block_sizes[i],
                                     &result));
    EXPECT_FALSE(result);
    EXPECT_TRUE(lib_.IsDeviceMounted("bar",
                                     kTestMounts,
                                     buffer,
                                     block_sizes[i],
                                     &result));
    EXPECT_FALSE(result);
  }
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledFalse) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(false));
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledTrue) {
  EXPECT_TRUE(lib_.AreMetricsEnabled());
}

void MetricsLibraryTest::VerifyEnabledCacheHit(bool to_value) {
  // We might step from one second to the next one time, but not 100
  // times in a row.
  for (int i = 0; i < 100; ++i) {
    lib_.cached_enabled_time_ = 0;
    EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
        .WillOnce(SetMetricsPolicy(!to_value));
    ASSERT_EQ(!to_value, lib_.AreMetricsEnabled());
    ON_CALL(*device_policy_, GetMetricsEnabled(_))
        .WillByDefault(SetMetricsPolicy(to_value));
    if (lib_.AreMetricsEnabled() == !to_value)
      return;
  }
  ADD_FAILURE() << "Did not see evidence of caching";
}

void MetricsLibraryTest::VerifyEnabledCacheEviction(bool to_value) {
  lib_.cached_enabled_time_ = 0;
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(!to_value));
  ASSERT_EQ(!to_value, lib_.AreMetricsEnabled());
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(to_value));
  ASSERT_LT(abs(static_cast<int>(time(nullptr) - lib_.cached_enabled_time_)),
            5);
  // Sleep one second (or cheat to be faster).
  --lib_.cached_enabled_time_;
  ASSERT_EQ(to_value, lib_.AreMetricsEnabled());
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledCaching) {
  VerifyEnabledCacheHit(false);
  VerifyEnabledCacheHit(true);
  VerifyEnabledCacheEviction(false);
  VerifyEnabledCacheEviction(true);
}

class CMetricsLibraryTest : public testing::Test {
 protected:
  virtual void SetUp() {
    lib_ = CMetricsLibraryNew();
    MetricsLibrary& ml = *reinterpret_cast<MetricsLibrary*>(lib_);
    EXPECT_TRUE(ml.uma_events_file_.empty());
    CMetricsLibraryInit(lib_);
    EXPECT_FALSE(ml.uma_events_file_.empty());
    ml.uma_events_file_ = kTestUMAEventsFile.value();
    EXPECT_EQ(0, WriteFile(kTestUMAEventsFile, "", 0));
    device_policy_ = new policy::MockDevicePolicy();
    EXPECT_CALL(*device_policy_, LoadPolicy())
        .Times(AnyNumber())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
        .Times(AnyNumber())
        .WillRepeatedly(SetMetricsPolicy(true));
    provider_ = new policy::PolicyProvider(device_policy_);
    ml.SetPolicyProvider(provider_);
    reinterpret_cast<MetricsLibrary*>(lib_)->cached_enabled_time_ = 0;
  }

  virtual void TearDown() {
    CMetricsLibraryDelete(lib_);
    base::DeleteFile(kTestUMAEventsFile, false);
  }

  CMetricsLibrary lib_;
  policy::MockDevicePolicy* device_policy_;
  policy::PolicyProvider* provider_;
};

TEST_F(CMetricsLibraryTest, AreMetricsEnabledFalse) {
  EXPECT_CALL(*device_policy_, GetMetricsEnabled(_))
      .WillOnce(SetMetricsPolicy(false));
  EXPECT_FALSE(CMetricsLibraryAreMetricsEnabled(lib_));
}

TEST_F(CMetricsLibraryTest, AreMetricsEnabledTrue) {
  EXPECT_TRUE(CMetricsLibraryAreMetricsEnabled(lib_));
}

int main(int argc, char** argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
