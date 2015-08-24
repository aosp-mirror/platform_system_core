/*
 * Copyright (C) 2010 The Android Open Source Project
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

#include "unclean_shutdown_collector.h"

#include <unistd.h>

#include <base/files/file_util.h>
#include <base/strings/string_util.h>
#include <chromeos/syslog_logging.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>

using base::FilePath;
using ::chromeos::FindLog;

namespace {

int s_crashes = 0;
bool s_metrics = true;

const char kTestDirectory[] = "test";
const char kTestSuspended[] = "test/suspended";
const char kTestUnclean[] = "test/unclean";

void CountCrash() {
  ++s_crashes;
}

bool IsMetrics() {
  return s_metrics;
}

}  // namespace

class UncleanShutdownCollectorMock : public UncleanShutdownCollector {
 public:
  MOCK_METHOD0(SetUpDBus, void());
};

class UncleanShutdownCollectorTest : public ::testing::Test {
  void SetUp() {
    s_crashes = 0;

    EXPECT_CALL(collector_, SetUpDBus()).WillRepeatedly(testing::Return());

    collector_.Initialize(CountCrash,
                          IsMetrics);
    rmdir(kTestDirectory);
    test_unclean_ = FilePath(kTestUnclean);
    collector_.unclean_shutdown_file_ = kTestUnclean;
    base::DeleteFile(test_unclean_, true);
    // Set up an alternate power manager state file as well
    collector_.powerd_suspended_file_ = FilePath(kTestSuspended);
    chromeos::ClearLog();
  }

 protected:
  void WriteStringToFile(const FilePath &file_path,
                         const char *data) {
    ASSERT_EQ(strlen(data), base::WriteFile(file_path, data, strlen(data)));
  }

  UncleanShutdownCollectorMock collector_;
  FilePath test_unclean_;
};

TEST_F(UncleanShutdownCollectorTest, EnableWithoutParent) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
}

TEST_F(UncleanShutdownCollectorTest, EnableWithParent) {
  mkdir(kTestDirectory, 0777);
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
}

TEST_F(UncleanShutdownCollectorTest, EnableCannotWrite) {
  collector_.unclean_shutdown_file_ = "/bad/path";
  ASSERT_FALSE(collector_.Enable());
  ASSERT_TRUE(FindLog("Unable to create shutdown check file"));
}

TEST_F(UncleanShutdownCollectorTest, CollectTrue) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
  ASSERT_TRUE(collector_.Collect());
  ASSERT_FALSE(base::PathExists(test_unclean_));
  ASSERT_EQ(1, s_crashes);
  ASSERT_TRUE(FindLog("Last shutdown was not clean"));
}

TEST_F(UncleanShutdownCollectorTest, CollectFalse) {
  ASSERT_FALSE(collector_.Collect());
  ASSERT_EQ(0, s_crashes);
}

TEST_F(UncleanShutdownCollectorTest, CollectDeadBatterySuspended) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
  base::WriteFile(collector_.powerd_suspended_file_, "", 0);
  ASSERT_FALSE(collector_.Collect());
  ASSERT_FALSE(base::PathExists(test_unclean_));
  ASSERT_FALSE(base::PathExists(collector_.powerd_suspended_file_));
  ASSERT_EQ(0, s_crashes);
  ASSERT_TRUE(FindLog("Unclean shutdown occurred while suspended."));
}

TEST_F(UncleanShutdownCollectorTest, Disable) {
  ASSERT_TRUE(collector_.Enable());
  ASSERT_TRUE(base::PathExists(test_unclean_));
  ASSERT_TRUE(collector_.Disable());
  ASSERT_FALSE(base::PathExists(test_unclean_));
  ASSERT_FALSE(collector_.Collect());
}

TEST_F(UncleanShutdownCollectorTest, DisableWhenNotEnabled) {
  ASSERT_TRUE(collector_.Disable());
}

TEST_F(UncleanShutdownCollectorTest, CantDisable) {
  mkdir(kTestDirectory, 0700);
  if (mkdir(kTestUnclean, 0700)) {
    ASSERT_EQ(EEXIST, errno)
        << "Error while creating directory '" << kTestUnclean
        << "': " << strerror(errno);
  }
  ASSERT_EQ(0, base::WriteFile(test_unclean_.Append("foo"), "", 0))
      << "Error while creating empty file '"
      << test_unclean_.Append("foo").value() << "': " << strerror(errno);
  ASSERT_FALSE(collector_.Disable());
  rmdir(kTestUnclean);
}
