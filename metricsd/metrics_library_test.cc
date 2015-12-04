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


#include <base/files/file_util.h>
#include <base/files/scoped_temp_dir.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "metrics/c_metrics_library.h"
#include "metrics/metrics_library.h"


class MetricsLibraryTest : public testing::Test {
 protected:
  virtual void SetUp() {
    ASSERT_TRUE(temp_dir_.CreateUniqueTempDir());
    lib_.InitForTest(temp_dir_.path());
    // Defeat metrics enabled caching between tests.
    lib_.cached_enabled_time_ = 0;
  }

  void SetMetricsConsent(bool enabled) {
    if (enabled) {
      ASSERT_EQ(base::WriteFile(lib_.consent_file_, "", 0), 0);
    } else {
      ASSERT_TRUE(base::DeleteFile(lib_.consent_file_, false));
    }
  }

  void VerifyEnabledCacheHit(bool to_value);
  void VerifyEnabledCacheEviction(bool to_value);

  MetricsLibrary lib_;
  base::ScopedTempDir temp_dir_;
};

TEST_F(MetricsLibraryTest, AreMetricsEnabledFalse) {
  SetMetricsConsent(false);
  EXPECT_FALSE(lib_.AreMetricsEnabled());
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledTrue) {
  SetMetricsConsent(true);
  EXPECT_TRUE(lib_.AreMetricsEnabled());
}

void MetricsLibraryTest::VerifyEnabledCacheHit(bool to_value) {
  // We might step from one second to the next one time, but not 100
  // times in a row.
  for (int i = 0; i < 100; ++i) {
    lib_.cached_enabled_time_ = 0;
    SetMetricsConsent(to_value);
    lib_.AreMetricsEnabled();
    // If we check the metrics status twice in a row, we use the cached value
    // the second time.
    SetMetricsConsent(!to_value);
    if (lib_.AreMetricsEnabled() == to_value)
      return;
  }
  ADD_FAILURE() << "Did not see evidence of caching";
}

void MetricsLibraryTest::VerifyEnabledCacheEviction(bool to_value) {
  lib_.cached_enabled_time_ = 0;
  SetMetricsConsent(!to_value);
  ASSERT_EQ(!to_value, lib_.AreMetricsEnabled());

  SetMetricsConsent(to_value);
  // Sleep one second (or cheat to be faster) and check that we are not using
  // the cached value.
  --lib_.cached_enabled_time_;
  ASSERT_EQ(to_value, lib_.AreMetricsEnabled());
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledCaching) {
  VerifyEnabledCacheHit(false);
  VerifyEnabledCacheHit(true);
  VerifyEnabledCacheEviction(false);
  VerifyEnabledCacheEviction(true);
}

TEST_F(MetricsLibraryTest, AreMetricsEnabledNoCaching) {
  // disable caching.
  lib_.use_caching_ = false;

  // Checking the consent repeatedly should return the right result.
  for (int i=0; i<100; ++i) {
    SetMetricsConsent(true);
    ASSERT_EQ(true, lib_.AreMetricsEnabled());
    SetMetricsConsent(false);
    ASSERT_EQ(false, lib_.AreMetricsEnabled());
  }
}
